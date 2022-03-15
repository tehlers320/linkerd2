//! Linkerd Policy Controller
//!
//! The policy controller serves discovery requests from inbound proxies, indicating how the proxy
//! should admit connections into a Pod. It watches the following cluster resources:
//!
//! - A `Namespace` may be annotated with a default-allow policy that applies to all pods in the
//!   namespace (unless they are annotated with a default policy).
//! - Each `Pod` enumerate its ports. We maintain an index of each pod's ports, linked to `Server`
//!   objects.
//! - Each `Server` selects over pods in the same namespace.
//! - Each `ServerAuthorization` selects over `Server` instances in the same namespace.  When a
//!   `ServerAuthorization` is updated, we find all of the `Server` instances it selects and update
//!   their authorizations and publishes these updates on the server's broadcast channel.
//!
//! ```text
//! [ Pod ] -> [ Port ] <- [ Server ] <- [ ServerAuthorization ]
//! ```
//!
//! Lookups against this index are are initiated for a single pod & port. The pod-port's state is
//! modeled as a nested watch -- the outer watch is updated as a `Server` selects/deselects a
//! pod-port; and the inner watch is updated as a `Server`'s authorizations are updated.
//!
//! The Pod, Server, and ServerAuthorization indices are all scoped within a namespace index, as
//! these resources cannot reference resources in other namespaces. This scoping helps to narrow the
//! search space when processing updates and linking resources.

#![deny(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]

mod defaults;

#[cfg(test)]
mod tests;

pub use self::defaults::DefaultPolicy;
use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use anyhow::Result;
use k8s::policy::server::Port;
use linkerd_policy_controller_core::{
    ClientAuthentication, ClientAuthorization, IdentityMatch, InboundServer, IpNet, ProxyProtocol,
};
use linkerd_policy_controller_k8s_api as k8s;
use parking_lot::RwLock;
use std::{collections::hash_map::Entry, sync::Arc};
use tokio::{sync::watch, time};

/// Holds cluster metadata.
#[derive(Clone, Debug)]
pub struct ClusterInfo {
    /// Networks including PodIPs in this cluster.
    ///
    /// Unfortunately, there's no way to discover this at runtime.
    pub networks: Vec<IpNet>,

    /// The namespace where the linkerd control plane is deployed
    pub control_plane_ns: String,

    /// The cluster's mesh identity trust domain.
    pub identity_domain: String,

    /// The cluster-wide default policy.
    pub default_policy: DefaultPolicy,

    /// The cluster-wide default protocol detection timeout.
    pub default_detect_timeout: time::Duration,
}

pub type SharedIndex = Arc<RwLock<Index>>;

/// Holds all indexing state. Owned and updated by a single task that processes watch events,
/// publishing results to the shared lookup map for quick lookups in the API server.
pub struct Index {
    /// Holds per-namespace pod/server/authorization indexes.
    namespaces: HashMap<String, NamespaceIndex>,

    cluster_info: ClusterInfo,
}

#[derive(Debug, Default)]
pub struct NamespaceIndex {
    /// Holds per-pod port indexes.
    pods: HashMap<String, PodMeta>,

    /// Holds servers by-name
    servers: HashMap<String, ServerMeta>,

    /// Holds server authorizations by-name
    server_authorizations: HashMap<String, ServerAuthorizationMeta>,
}

#[derive(Debug, PartialEq)]
pub enum ServerSelector {
    Name(String),
    Selector(k8s::labels::Selector),
}

#[derive(Debug)]
struct PodMeta {
    name: String,
    labels: k8s::Labels,
    port_names: HashMap<String, HashSet<u16>>,
    port_servers: HashMap<u16, PodPortServer>,
    default_policy: DefaultPolicy,
}

#[derive(Debug)]
struct PodPortServer {
    name: Option<String>,
    tx: watch::Sender<InboundServer>,
    rx: watch::Receiver<InboundServer>,
}

#[derive(Debug, PartialEq)]
struct ServerMeta {
    labels: k8s::Labels,
    pod_selector: k8s::labels::Selector,
    port_ref: Port,
    protocol: ProxyProtocol,
}

#[derive(Debug, PartialEq)]
struct ServerAuthorizationMeta {
    authz: ClientAuthorization,
    server_selector: ServerSelector,
}

// === impl Index ===

impl Index {
    pub fn shared(cluster_info: ClusterInfo) -> SharedIndex {
        Arc::new(RwLock::new(Self {
            cluster_info,
            namespaces: HashMap::default(),
        }))
    }

    pub fn get_ns(&self, ns: &str) -> Option<&NamespaceIndex> {
        self.namespaces.get(ns)
    }

    pub fn get_ns_or_default(&mut self, ns: impl ToString) -> &mut NamespaceIndex {
        self.namespaces.entry(ns.to_string()).or_default()
    }

    pub fn get_pod_server(
        &mut self,
        ns: &str,
        pod: &str,
        port: u16,
    ) -> Result<watch::Receiver<InboundServer>> {
        let ns = self
            .namespaces
            .get_mut(ns)
            .ok_or_else(|| anyhow::anyhow!("namespace not found: {}", ns))?;
        ns.get_pod_server(pod, port, &self.cluster_info)
    }
}

impl NamespaceIndex {
    /// Adds or updates a Pod.
    ///
    /// Labels may be updated but port names may not be updated after a pod is created.
    ///
    /// Returns true if the Pod was updated and false if it already existed and was unchanged.
    pub fn apply_pod(
        &mut self,
        name: impl ToString,
        labels: k8s::Labels,
        port_names: HashMap<String, HashSet<u16>>,
        default_policy: DefaultPolicy,
    ) -> Result<bool> {
        match self.pods.entry(name.to_string()) {
            // Pod labels may change at runtime but the default policy and port sets may not.
            Entry::Occupied(pod) => {
                let pod = pod.into_mut();
                if pod.port_names != port_names {
                    anyhow::bail!("pod {} port names must not change", name.to_string());
                }
                if pod.default_policy != default_policy {
                    anyhow::bail!("pod {} default policy must not change", name.to_string());
                }

                if pod.labels == labels {
                    Ok(false)
                } else {
                    pod.labels = labels;
                    Ok(true)
                }
            }

            Entry::Vacant(entry) => {
                let name = entry.key().to_string();
                entry.insert(PodMeta {
                    name,
                    labels,
                    port_names,
                    default_policy,
                    port_servers: HashMap::default(),
                });
                Ok(true)
            }
        }
    }

    /// Deletes a Pod from the index.
    ///
    /// Returns true if the Pod was deleted and false if it did not exist.
    pub fn delete_pod(&mut self, name: &str) -> bool {
        self.pods.remove(name).is_some()
    }

    /// Adds or updates a Server.
    ///
    /// Returns true if the Server was updated and false if it already existed and was unchanged.
    pub fn apply_server(
        &mut self,
        name: impl ToString,
        labels: k8s::Labels,
        pod_selector: k8s::labels::Selector,
        port_ref: Port,
        protocol: ProxyProtocol,
    ) -> bool {
        let meta = ServerMeta {
            labels,
            pod_selector,
            port_ref,
            protocol,
        };
        match self.servers.entry(name.to_string()) {
            Entry::Occupied(entry) => {
                let srv = entry.into_mut();
                if *srv == meta {
                    false
                } else {
                    *srv = meta;
                    true
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(meta);
                true
            }
        }
    }

    /// Deletes a Server from the index.
    ///
    /// Returns true if the Server was deleted and false if it did not exist.
    pub fn delete_server(&mut self, name: &str) -> bool {
        self.servers.remove(name).is_some()
    }

    /// Adds or updates a ServerAuthorization.
    ///
    /// Returns true if the ServerAuthorization was updated and false if it already existed and was
    /// unchanged.
    pub fn apply_server_authorization(
        &mut self,
        name: impl ToString,
        server_selector: ServerSelector,
        authz: ClientAuthorization,
    ) -> bool {
        let meta = ServerAuthorizationMeta {
            authz,
            server_selector,
        };
        match self.server_authorizations.entry(name.to_string()) {
            Entry::Occupied(entry) => {
                let saz = entry.into_mut();
                if *saz == meta {
                    false
                } else {
                    *saz = meta;
                    true
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(meta);
                true
            }
        }
    }

    /// Deletes a ServerAuthorization from the index.
    ///
    /// Returns true if the ServerAuthorization was deleted and false if it did not exist.
    pub fn delete_server_authorization(&mut self, name: &str) -> bool {
        self.server_authorizations.remove(name).is_some()
    }

    /// Reindex all pod-server-authorization relationships.
    pub fn reindex(&mut self) {
        tracing::trace!(servers = %self.servers.len(), "reindexing");
        for (srvname, srv) in self.servers.iter() {
            tracing::trace!(server = %srvname, "reindexing");
            let server = self.mk_inbound_server(srvname.to_string(), srv);

            for pod in self.pods.values_mut() {
                if srv.pod_selector.matches(&pod.labels) {
                    tracing::trace!(server = %srvname, %pod.name, "adding server to pod");
                    // A server may select more than one port on a pod.
                    for port in pod.get_ports_by_name(&srv.port_ref).into_iter() {
                        tracing::trace!(server = %srvname, %pod.name, %port, "associating server with pod");
                        if let Err(conflict) =
                            Self::associate_pod_with_server(pod, port, &server, &self.servers)
                        {
                            tracing::warn!(%conflict);
                            continue;
                        };
                    }
                } else {
                    tracing::trace!(
                        server = %srvname,
                        selector = ?srv.pod_selector,
                        %pod.name,
                        ?pod.labels,
                        "does not match"
                    );
                }
            }
        }
    }

    fn associate_pod_with_server(
        pod: &mut PodMeta,
        port: u16,
        server: &InboundServer,
        servers: &HashMap<String, ServerMeta>,
    ) -> Result<bool> {
        match pod.port_servers.entry(port) {
            Entry::Occupied(entry) => {
                let ps = entry.get();
                if *ps.rx.borrow() == *server {
                    return Ok(false);
                }

                if let Some(psn) = ps.name.as_deref() {
                    if psn != server.name && servers.contains_key(psn) {
                        anyhow::bail!(
                            "both {} and {} select {}:{}",
                            psn,
                            server.name,
                            pod.name,
                            port,
                        );
                    }
                }

                ps.tx
                    .send(server.clone())
                    .expect("a receiver is held by the index");
                Ok(true)
            }

            Entry::Vacant(entry) => {
                let (tx, rx) = watch::channel(server.clone());
                entry.insert(PodPortServer {
                    name: Some(server.name.clone()),
                    tx,
                    rx,
                });
                Ok(true)
            }
        }
    }

    fn mk_inbound_server(&self, name: String, server: &ServerMeta) -> InboundServer {
        let mut authorizations = HashMap::with_capacity(self.server_authorizations.len());
        for (sazname, saz) in self.server_authorizations.iter() {
            let matched = match &saz.server_selector {
                ServerSelector::Name(n) => *n == name,
                ServerSelector::Selector(selector) => selector.matches(&server.labels),
            };
            if matched {
                authorizations.insert(sazname.to_string(), saz.authz.clone());
            }
        }
        InboundServer {
            name,
            protocol: server.protocol.clone(),
            authorizations,
        }
    }

    /// Attempts to find a Server for the given pod and port.
    ///
    /// If the pod does not exist, an error is returned.
    ///
    /// If the port is not known, a default server is created.
    fn get_pod_server(
        &mut self,
        name: &str,
        port: u16,
        config: &ClusterInfo,
    ) -> Result<watch::Receiver<InboundServer>> {
        let pod = self
            .pods
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("pod {} not found", name))?;
        Ok(pod.get_or_default(port, config).rx.clone())
    }
}

// === impl PodMeta ===

impl PodMeta {
    fn get_ports_by_name(&mut self, port_ref: &Port) -> Vec<u16> {
        match port_ref {
            Port::Number(p) => Some(*p).into_iter().collect(),
            Port::Name(name) => self
                .port_names
                .get(name)
                .cloned()
                .into_iter()
                .flatten()
                .collect(),
        }
    }

    fn get_or_default(&mut self, port: u16, config: &ClusterInfo) -> &mut PodPortServer {
        self.port_servers.entry(port).or_insert_with(|| {
            let mut authorizations = HashMap::default();
            if let DefaultPolicy::Allow {
                authenticated_only,
                cluster_only,
            } = self.default_policy
            {
                let authentication = if authenticated_only {
                    ClientAuthentication::TlsAuthenticated(vec![IdentityMatch::Suffix(vec![])])
                } else {
                    ClientAuthentication::Unauthenticated
                };
                let networks = if cluster_only {
                    config.networks.iter().copied().map(Into::into).collect()
                } else {
                    vec![
                        "0.0.0.0/0".parse::<IpNet>().unwrap().into(),
                        "::/0".parse::<IpNet>().unwrap().into(),
                    ]
                };
                authorizations.insert(
                    format!("default:{}", self.default_policy),
                    ClientAuthorization {
                        authentication,
                        networks,
                    },
                );
            };

            let (tx, rx) = watch::channel(InboundServer {
                name: format!("default:{}", self.default_policy),
                protocol: ProxyProtocol::Detect {
                    timeout: tokio::time::Duration::from_secs(1), // FIXME
                },
                authorizations,
            });
            PodPortServer { name: None, tx, rx }
        })
    }
}
