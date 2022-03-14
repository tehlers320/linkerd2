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
#![allow(dead_code, unused_variables)]

mod defaults;
// mod lookup;
// mod namespace;
// pub mod pod;
// pub mod server;
// pub mod server_authorization;

// #[cfg(test)]
// mod tests;

pub use self::defaults::DefaultPolicy;
use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use anyhow::Result;
use k8s::policy::server::Port;
use linkerd_policy_controller_core::{ClientAuthorization, InboundServer, IpNet, ProxyProtocol};
use linkerd_policy_controller_k8s_api as k8s;
use parking_lot::RwLock;
use std::{collections::hash_map, sync::Arc};
use tokio::{sync::watch, time};

// /// Watches a server's configuration for server/authorization changes.
// type ServerRx = watch::Receiver<InboundServer>;

// /// Publishes updates for a server's configuration for server/authorization changes.
// type ServerTx = watch::Sender<InboundServer>;

// /// Watches a pod's port for a new `ServerRx`.
// type PodServerRx = watch::Receiver<ServerRx>;

// /// Publishes a pod's port for a new `ServerRx`.
// type PodServerTx = watch::Sender<ServerRx>;

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
}

pub type SharedIndex = Arc<RwLock<Index>>;

/// Holds all indexing state. Owned and updated by a single task that processes watch events,
/// publishing results to the shared lookup map for quick lookups in the API server.
pub struct Index {
    /// Holds per-namespace pod/server/authorization indexes.
    namespaces: HashMap<String, NamespaceIndex>,

    cluster_info: ClusterInfo,

    /*
        /// Holds watches for the cluster's default-allow policies. These watches are never updated but
        /// this state is held so we can used shared references when updating a pod-port's server watch
        /// with a default policy.
        default_policy_watches: DefaultPolicyWatches,
    */
    default_policy: DefaultPolicy,
}

#[derive(Debug)]
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

#[derive(Debug, Default)]
struct PodMeta {
    labels: k8s::Labels,
    port_names: HashMap<String, HashSet<u16>>,
    port_servers: HashMap<u16, PodPortServer>,
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
    pub fn shared(
        cluster_info: ClusterInfo,
        default_policy: DefaultPolicy,
        detect_timeout: time::Duration,
    ) -> SharedIndex {
        // // Create a common set of receivers for all supported default policies.
        // let default_policy_watches =
        //     DefaultPolicyWatches::new(cluster_info.networks.clone(), detect_timeout);

        Arc::new(RwLock::new(Self {
            cluster_info,
            default_policy,
            //default_policy_watches,
            namespaces: HashMap::default(),
        }))
    }

    pub fn get_ns(&self, ns: &str) -> Option<&NamespaceIndex> {
        self.namespaces.get(ns)
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
    ) -> Result<bool> {
        match self.pods.entry(name.to_string()) {
            hash_map::Entry::Occupied(pod) => {
                let pod = pod.into_mut();
                if pod.port_names != port_names {
                    // This would indicate that the pod's port list is mutated after it's created,
                    // which is impossible.
                    anyhow::bail!("pod {} port names changed", name.to_string());
                }

                if pod.labels == labels {
                    Ok(false)
                } else {
                    pod.labels = labels;
                    Ok(true)
                }
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(PodMeta {
                    labels,
                    port_names,
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
            hash_map::Entry::Occupied(entry) => {
                let srv = entry.into_mut();
                if *srv == meta {
                    false
                } else {
                    *srv = meta;
                    true
                }
            }
            hash_map::Entry::Vacant(entry) => {
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
    /// Returns true if the ServerAuthorization was updated and false if it already existed and was unchanged.
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
            hash_map::Entry::Occupied(entry) => {
                let saz = entry.into_mut();
                if *saz == meta {
                    false
                } else {
                    *saz = meta;
                    true
                }
            }
            hash_map::Entry::Vacant(entry) => {
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
    pub fn reindex(&mut self) -> bool {
        let mut updated = false;

        for (srvname, srvmeta) in self.servers.iter() {
            let server = {
                let mut authorizations = HashMap::with_capacity(self.server_authorizations.len());
                for (sazname, sazmeta) in self.server_authorizations.iter() {
                    let matched = match sazmeta.server_selector {
                        ServerSelector::Name(ref n) => n == srvname,
                        ServerSelector::Selector(ref selector) => selector.matches(&srvmeta.labels),
                    };
                    if matched {
                        authorizations.insert(sazname.clone(), sazmeta.authz.clone());
                    }
                }
                InboundServer {
                    name: srvname.clone(),
                    protocol: srvmeta.protocol.clone(),
                    authorizations,
                }
            };

            for (podname, podmeta) in self.pods.iter_mut() {
                if srvmeta.pod_selector.matches(&podmeta.labels) {
                    for port in podmeta.get_ports(&srvmeta.port_ref).into_iter() {
                        match podmeta.port_servers.entry(port) {
                            hash_map::Entry::Occupied(entry) => {
                                let ps = entry.get();
                                if *ps.rx.borrow() != server {
                                    if let Some(psn) = ps.name.as_deref() {
                                        if psn != server.name && self.servers.contains_key(psn) {
                                            tracing::warn!(
                                                "Both {} and {} select pod {} on port {}",
                                                psn,
                                                server.name,
                                                podname,
                                                port,
                                            );
                                            continue;
                                        }
                                    }
                                    ps.tx
                                        .send(server.clone())
                                        .expect("at least one receiver must be held");
                                    updated = true;
                                }
                            }
                            hash_map::Entry::Vacant(entry) => {
                                let (tx, rx) = watch::channel(server.clone());
                                entry.insert(PodPortServer {
                                    name: Some(podname.clone()),
                                    tx,
                                    rx,
                                });
                                updated = true;
                            }
                        }
                    }
                }
            }
        }

        updated
    }

    // TODO: We should provide a way for the gRPC server to initiate a watch, even if the server
    // didn't already have a server for this port. Fails if the pod is not known.
    pub fn lookup(&mut self, name: &str, port: u16) -> Result<watch::Receiver<InboundServer>> {
        unimplemented!()
    }
}

// === impl PodMeta ===

impl PodMeta {
    fn get_ports(&mut self, port_ref: &Port) -> Vec<u16> {
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
}
