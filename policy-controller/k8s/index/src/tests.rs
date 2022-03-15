use super::*;
use ahash::AHashMap as HashMap;
use linkerd_policy_controller_core::{
    ClientAuthentication, ClientAuthorization, IdentityMatch, IpNet, Ipv4Net, Ipv6Net,
    NetworkMatch, ProxyProtocol,
};
use tokio::time;

#[test]
fn pod_must_exist_for_lookup() {
    let test = TestConfig::default();
    test.index
        .write()
        .get_pod_server("ns-0", "pod-0", 8080)
        .expect_err("pod-0.ns-0 must not exist");
}

#[test]
fn links_named_server_port() {
    let test = TestConfig::default();

    let default_policy = test.default_policy;
    test.with_ns_reindexed("ns-0", |ns| {
        let mut ports = HashMap::with_capacity(1);
        ports.insert("admin-http".to_string(), Some(8080).into_iter().collect());
        ns.apply_pod(
            "pod-0",
            Some(("app", "app-0")).into_iter().collect(),
            ports,
            default_policy,
        )
    })
    .expect("pod-0.ns-0 should not already exist");

    let mut rx = test
        .index
        .write()
        .get_pod_server("ns-0", "pod-0", 8080)
        .expect("pod-0.ns-0 should exist");
    assert_eq!(*rx.borrow_and_update(), test.default_server());

    assert!(test.with_ns_reindexed("ns-0", |ns| ns.apply_server(
        "srv-admin-http",
        Default::default(),
        Some(("app", "app-0")).into_iter().collect(),
        Port::Name("admin-http".to_string()),
        ProxyProtocol::Http1,
    )));
    assert!(rx.has_changed().unwrap());
    assert_eq!(
        *rx.borrow_and_update(),
        InboundServer {
            name: "srv-admin-http".to_string(),
            authorizations: Default::default(),
            protocol: ProxyProtocol::Http1,
        },
    );
}

#[test]
fn links_unnamed_server_port() {
    let test = TestConfig::default();

    let default_policy = test.default_policy;
    test.with_ns_reindexed("ns-0", |ns| {
        ns.apply_pod(
            "pod-0",
            Some(("app", "app-0")).into_iter().collect(),
            HashMap::default(),
            default_policy,
        )
    })
    .expect("pod-0.ns-0 should not already exist");

    let mut rx = test
        .index
        .write()
        .get_pod_server("ns-0", "pod-0", 8080)
        .expect("pod-0.ns-0 should exist");
    assert_eq!(*rx.borrow_and_update(), test.default_server());

    assert!(test.with_ns_reindexed("ns-0", |ns| ns.apply_server(
        "srv-8080",
        Default::default(),
        Some(("app", "app-0")).into_iter().collect(),
        Port::Number(8080),
        ProxyProtocol::Http1,
    )));
    assert!(rx.has_changed().unwrap());
    assert_eq!(
        *rx.borrow_and_update(),
        InboundServer {
            name: "srv-8080".to_string(),
            authorizations: Default::default(),
            protocol: ProxyProtocol::Http1,
        },
    );
}

#[test]
fn links_server_authz_by_name() {
    let test = TestConfig::default();

    let default_policy = test.default_policy;
    test.with_ns_reindexed("ns-0", |ns| {
        ns.apply_pod(
            "pod-0",
            Some(("app", "app-0")).into_iter().collect(),
            HashMap::default(),
            default_policy,
        )
    })
    .expect("pod-0.ns-0 should not already exist");

    let mut rx = test
        .index
        .write()
        .get_pod_server("ns-0", "pod-0", 8080)
        .expect("pod-0.ns-0 should exist");
    assert_eq!(*rx.borrow_and_update(), test.default_server());

    assert!(test.with_ns_reindexed("ns-0", |ns| ns.apply_server(
        "srv-8080",
        Default::default(),
        Some(("app", "app-0")).into_iter().collect(),
        Port::Number(8080),
        ProxyProtocol::Http1,
    )));
    assert!(rx.has_changed().unwrap());
    assert_eq!(
        *rx.borrow_and_update(),
        InboundServer {
            name: "srv-8080".to_string(),
            authorizations: Default::default(),
            protocol: ProxyProtocol::Http1,
        },
    );

    let authz = ClientAuthorization {
        networks: vec!["10.0.0.0/8".parse::<IpNet>().unwrap().into()],
        authentication: ClientAuthentication::TlsAuthenticated(vec![IdentityMatch::Exact(
            "foo.bar".to_string(),
        )]),
    };
    assert!(
        test.with_ns_reindexed("ns-0", |ns| ns.apply_server_authorization(
            "authz-foo",
            ServerSelector::Name("srv-8080".to_string()),
            authz.clone()
        ))
    );
    assert!(rx.has_changed().unwrap());
    assert_eq!(
        *rx.borrow(),
        InboundServer {
            name: "srv-8080".to_string(),
            authorizations: Some(("authz-foo".to_string(), authz)).into_iter().collect(),
            protocol: ProxyProtocol::Http1,
        },
    );
}

#[test]
fn links_server_authz_by_label() {
    let test = TestConfig::default();

    let default_policy = test.default_policy;
    test.with_ns_reindexed("ns-0", |ns| {
        ns.apply_pod(
            "pod-0",
            Some(("app", "app-0")).into_iter().collect(),
            HashMap::default(),
            default_policy,
        )
    })
    .expect("pod-0.ns-0 should not already exist");

    let mut rx = test
        .index
        .write()
        .get_pod_server("ns-0", "pod-0", 8080)
        .expect("pod-0.ns-0 should exist");
    assert_eq!(*rx.borrow_and_update(), test.default_server());

    assert!(test.with_ns_reindexed("ns-0", |ns| ns.apply_server(
        "srv-8080",
        Some(("app", "app-0")).into_iter().collect(),
        Some(("app", "app-0")).into_iter().collect(),
        Port::Number(8080),
        ProxyProtocol::Http1,
    )));
    assert!(rx.has_changed().unwrap());
    assert_eq!(
        *rx.borrow_and_update(),
        InboundServer {
            name: "srv-8080".to_string(),
            authorizations: Default::default(),
            protocol: ProxyProtocol::Http1,
        },
    );

    let authz = ClientAuthorization {
        networks: vec!["10.0.0.0/8".parse::<IpNet>().unwrap().into()],
        authentication: ClientAuthentication::TlsAuthenticated(vec![IdentityMatch::Exact(
            "foo.bar".to_string(),
        )]),
    };
    assert!(
        test.with_ns_reindexed("ns-0", |ns| ns.apply_server_authorization(
            "authz-foo",
            ServerSelector::Selector(Some(("app", "app-0")).into_iter().collect()),
            authz.clone()
        ))
    );
    assert!(rx.has_changed().unwrap());
    assert_eq!(
        *rx.borrow(),
        InboundServer {
            name: "srv-8080".to_string(),
            authorizations: Some(("authz-foo".to_string(), authz)).into_iter().collect(),
            protocol: ProxyProtocol::Http1,
        },
    );
}

#[cfg(feature = "fixme")]
#[tokio::test]
async fn server_update_deselects_pod() {
    let cluster_net = IpNet::from_str("192.0.2.0/24").unwrap();
    let cluster = ClusterInfo {
        networks: vec![cluster_net],
        control_plane_ns: "linkerd".to_string(),
        identity_domain: "cluster.example.com".into(),
    };
    let pod_net = IpNet::from_str("192.0.2.2/28").unwrap();
    let detect_timeout = time::Duration::from_secs(1);
    let default = DefaultPolicy::Allow {
        authenticated_only: false,
        cluster_only: true,
    };
    let idx = Index::shared(cluster, default, detect_timeout);

    let p = mk_pod(
        "ns-0",
        "pod-0",
        "node-0",
        pod_net.hosts().next().unwrap(),
        Some(("container-0", vec![2222])),
    );
    pods.restart(vec![p.clone()]).await;

    let srv = {
        let mut srv = mk_server("ns-0", "srv-0", Port::Number(2222), None, None);
        srv.spec.proxy_protocol = Some(k8s::policy::server::ProxyProtocol::Http2);
        srv
    };
    servers.restart(vec![srv.clone()]).await;

    // The default policy applies for all exposed ports.
    let port2222 = lookup_rx.lookup("ns-0", "pod-0", 2222).unwrap();
    assert_eq!(
        port2222.get(),
        InboundServer {
            name: "srv-0".into(),
            protocol: ProxyProtocol::Http2,
            authorizations: Default::default(),
        }
    );

    servers
        .apply({
            let mut srv = srv;
            srv.spec.pod_selector = Some(("label", "value")).into_iter().collect();
            srv
        })
        .await;
    assert_eq!(
        port2222.get(),
        InboundServer {
            name: format!("default:{}", default),
            authorizations: mk_default_policy(default, cluster_net),
            protocol: ProxyProtocol::Detect {
                timeout: detect_timeout,
            },
        }
    );
}

/// Tests that pod servers are configured with defaults based on the global `DefaultPolicy` policy.
///
/// Iterates through each default policy and validates that it produces expected configurations.
#[cfg(feature = "fixme")]
#[tokio::test]
async fn default_policy_global() {
    let cluster_net = IpNet::from_str("192.0.2.0/24").unwrap();
    let cluster = ClusterInfo {
        networks: vec![cluster_net],
        control_plane_ns: "linkerd".to_string(),
        identity_domain: "cluster.example.com".into(),
    };
    let pod_net = IpNet::from_str("192.0.2.2/28").unwrap();
    let detect_timeout = time::Duration::from_secs(1);

    for default in &DEFAULTS {
        let idx = Index::shared(cluster.clone(), *default, detect_timeout);
        let mut pods = mock(idx, crate::pod::index);

        let p = mk_pod(
            "ns-0",
            "pod-0",
            "node-0",
            pod_net.hosts().next().unwrap(),
            Some(("container-0", vec![2222])),
        );
        pods.restart(vec![p]).await;

        let config = InboundServer {
            name: format!("default:{}", default),
            authorizations: mk_default_policy(*default, cluster_net),
            protocol: ProxyProtocol::Detect {
                timeout: detect_timeout,
            },
        };

        // Lookup port 2222 -> default config.
        let port2222 = lookup_rx
            .lookup("ns-0", "pod-0", 2222)
            .expect("pod must exist in lookups");
        assert_eq!(port2222.get(), config);
    }
}

/// Tests that pod servers are configured with defaults based on the workload-defined `DefaultPolicy`
/// policy.
///
/// Iterates through each default policy and validates that it produces expected configurations.
#[cfg(feature = "fixme")]
#[tokio::test]
async fn default_policy_annotated() {
    let cluster_net = IpNet::from_str("192.0.2.0/24").unwrap();
    let cluster = ClusterInfo {
        networks: vec![cluster_net],
        control_plane_ns: "linkerd".to_string(),
        identity_domain: "cluster.example.com".into(),
    };
    let pod_net = IpNet::from_str("192.0.2.2/28").unwrap();
    let detect_timeout = time::Duration::from_secs(1);

    for default in &DEFAULTS {
        let idx = Index::shared(
            cluster.clone(),
            // Invert default to ensure override applies.
            match *default {
                DefaultPolicy::Deny => DefaultPolicy::Allow {
                    authenticated_only: false,
                    cluster_only: false,
                },
                _ => DefaultPolicy::Deny,
            },
            detect_timeout,
        );

        let mut pods = mock(idx, crate::pod::index);

        let mut p = mk_pod(
            "ns-0",
            "pod-0",
            "node-0",
            pod_net.hosts().next().unwrap(),
            Some(("container-0", vec![2222])),
        );
        p.annotations_mut()
            .insert(DefaultPolicy::ANNOTATION.into(), default.to_string());
        pods.restart(vec![p]).await;

        let config = InboundServer {
            name: format!("default:{}", default),
            authorizations: mk_default_policy(*default, cluster_net),
            protocol: ProxyProtocol::Detect {
                timeout: detect_timeout,
            },
        };

        let port2222 = lookup_rx
            .lookup("ns-0", "pod-0", 2222)
            .expect("pod must exist in lookups");
        assert_eq!(port2222.get(), config);
    }
}
/// Tests that an invalid workload annotation is ignored in favor of the global default.
#[cfg(feature = "fixme")]
#[tokio::test]
async fn default_policy_annotated_invalid() {
    let cluster_net = IpNet::from_str("192.0.2.0/24").unwrap();
    let cluster = ClusterInfo {
        networks: vec![cluster_net],
        control_plane_ns: "linkerd".to_string(),
        identity_domain: "cluster.example.com".into(),
    };
    let pod_net = IpNet::from_str("192.0.2.2/28").unwrap();
    let detect_timeout = time::Duration::from_secs(1);

    let default = DefaultPolicy::Allow {
        authenticated_only: false,
        cluster_only: false,
    };
    let idx = Index::shared(cluster, default, detect_timeout);
    let mut pods = mock(idx, crate::pod::index);

    let mut p = mk_pod(
        "ns-0",
        "pod-0",
        "node-0",
        pod_net.hosts().next().unwrap(),
        Some(("container-0", vec![2222])),
    );
    p.annotations_mut()
        .insert(DefaultPolicy::ANNOTATION.into(), "bogus".into());
    pods.restart(vec![p]).await;

    // Lookup port 2222 -> default config.
    let port2222 = lookup_rx
        .lookup("ns-0", "pod-0", 2222)
        .expect("pod must exist in lookups");
    assert_eq!(
        port2222.get(),
        InboundServer {
            name: format!("default:{}", default),
            authorizations: mk_default_policy(
                DefaultPolicy::Allow {
                    authenticated_only: false,
                    cluster_only: false,
                },
                cluster_net,
            ),
            protocol: ProxyProtocol::Detect {
                timeout: detect_timeout,
            },
        }
    );
}

#[cfg(feature = "fixme")]
#[tokio::test]
async fn opaque_annotated() {
    let cluster_net = IpNet::from_str("192.0.2.0/24").unwrap();
    let cluster = ClusterInfo {
        networks: vec![cluster_net],
        control_plane_ns: "linkerd".to_string(),
        identity_domain: "cluster.example.com".into(),
    };
    let pod_net = IpNet::from_str("192.0.2.2/28").unwrap();
    let detect_timeout = time::Duration::from_secs(1);

    for default in &DEFAULTS {
        let idx = Index::shared(cluster.clone(), *default, detect_timeout);
        let mut pods = mock(idx, crate::pod::index);

        let mut p = mk_pod(
            "ns-0",
            "pod-0",
            "node-0",
            pod_net.hosts().next().unwrap(),
            Some(("container-0", vec![2222])),
        );
        p.annotations_mut()
            .insert("config.linkerd.io/opaque-ports".into(), "2222".into());
        pods.restart(vec![p]).await;

        let config = InboundServer {
            name: format!("default:{}", default),
            authorizations: mk_default_policy(*default, cluster_net),
            protocol: ProxyProtocol::Opaque,
        };

        let port2222 = lookup_rx
            .lookup("ns-0", "pod-0", 2222)
            .expect("pod must exist in lookups");
        assert_eq!(port2222.get(), config);
    }
}

#[cfg(feature = "fixme")]
#[tokio::test]
async fn authenticated_annotated() {
    let cluster_net = IpNet::from_str("192.0.2.0/24").unwrap();
    let cluster = ClusterInfo {
        networks: vec![cluster_net],
        control_plane_ns: "linkerd".to_string(),
        identity_domain: "cluster.example.com".into(),
    };
    let pod_net = IpNet::from_str("192.0.2.2/28").unwrap();
    let detect_timeout = time::Duration::from_secs(1);

    for default in &DEFAULTS {
        let idx = Index::shared(cluster.clone(), *default, detect_timeout);
        let mut pods = mock(idx, crate::pod::index);

        let mut p = mk_pod(
            "ns-0",
            "pod-0",
            "node-0",
            pod_net.hosts().next().unwrap(),
            Some(("container-0", vec![2222])),
        );
        p.annotations_mut().insert(
            "config.linkerd.io/proxy-require-identity-inbound-ports".into(),
            "2222".into(),
        );
        pods.restart(vec![p]).await;

        let config = {
            let policy = match *default {
                DefaultPolicy::Allow { cluster_only, .. } => DefaultPolicy::Allow {
                    cluster_only,
                    authenticated_only: true,
                },
                DefaultPolicy::Deny => DefaultPolicy::Deny,
            };
            InboundServer {
                name: format!("default:{}", policy),
                authorizations: mk_default_policy(policy, cluster_net),
                protocol: ProxyProtocol::Detect {
                    timeout: detect_timeout,
                },
            }
        };

        let port2222 = lookup_rx
            .lookup("ns-0", "pod-0", 2222)
            .expect("pod must exist in lookups");
        assert_eq!(port2222.get().protocol, config.protocol);
        assert_eq!(port2222.get().authorizations, config.authorizations);
    }
}

// === Helpers ===

const DEFAULTS: [DefaultPolicy; 5] = [
    DefaultPolicy::Deny,
    DefaultPolicy::Allow {
        authenticated_only: true,
        cluster_only: false,
    },
    DefaultPolicy::Allow {
        authenticated_only: false,
        cluster_only: false,
    },
    DefaultPolicy::Allow {
        authenticated_only: true,
        cluster_only: true,
    },
    DefaultPolicy::Allow {
        authenticated_only: false,
        cluster_only: true,
    },
];

fn mk_default_policy(
    da: DefaultPolicy,
    cluster_nets: Vec<IpNet>,
) -> HashMap<String, ClientAuthorization> {
    let all_nets = vec![Ipv4Net::default().into(), Ipv6Net::default().into()];

    let cluster_nets = cluster_nets.into_iter().map(NetworkMatch::from).collect();

    let authed = ClientAuthentication::TlsAuthenticated(vec![IdentityMatch::Suffix(vec![])]);

    match da {
        DefaultPolicy::Deny => None,
        DefaultPolicy::Allow {
            authenticated_only: true,
            cluster_only: false,
        } => Some((
            "default:all-authenticated".into(),
            ClientAuthorization {
                authentication: authed,
                networks: all_nets,
            },
        )),
        DefaultPolicy::Allow {
            authenticated_only: false,
            cluster_only: false,
        } => Some((
            "default:all-unauthenticated".into(),
            ClientAuthorization {
                authentication: ClientAuthentication::Unauthenticated,
                networks: all_nets,
            },
        )),
        DefaultPolicy::Allow {
            authenticated_only: true,
            cluster_only: true,
        } => Some((
            "default:cluster-authenticated".into(),
            ClientAuthorization {
                authentication: authed,
                networks: cluster_nets,
            },
        )),
        DefaultPolicy::Allow {
            authenticated_only: false,
            cluster_only: true,
        } => Some((
            "default:cluster-unauthenticated".into(),
            ClientAuthorization {
                authentication: ClientAuthentication::Unauthenticated,
                networks: cluster_nets,
            },
        )),
    }
    .into_iter()
    .collect()
}

fn init_tracing() -> tracing::subscriber::DefaultGuard {
    tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
}

struct TestConfig {
    index: SharedIndex,
    detect_timeout: time::Duration,
    default_policy: DefaultPolicy,
    cluster: ClusterInfo,
    _tracing: tracing::subscriber::DefaultGuard,
}

impl TestConfig {
    fn with_ns_reindexed<T>(&self, ns: &str, f: impl FnOnce(&mut NamespaceIndex) -> T) -> T {
        let mut idx = self.index.write();
        let ns = idx.get_ns_or_default(ns);
        let t = f(ns);
        ns.reindex();
        t
    }

    fn default_server(&self) -> InboundServer {
        InboundServer {
            name: format!("default:{}", self.default_policy),
            authorizations: mk_default_policy(self.default_policy, self.cluster.networks.clone()),
            protocol: ProxyProtocol::Detect {
                timeout: self.detect_timeout,
            },
        }
    }
}

impl Default for TestConfig {
    fn default() -> TestConfig {
        let _tracing = init_tracing();
        let cluster_net = "192.0.2.0/24".parse().unwrap();
        let cluster = ClusterInfo {
            networks: vec![cluster_net],
            control_plane_ns: "linkerd".to_string(),
            identity_domain: "cluster.example.com".into(),
        };
        let detect_timeout = time::Duration::from_secs(1);
        let default_policy = DefaultPolicy::Allow {
            authenticated_only: false,
            cluster_only: true,
        };
        let index = Index::shared(cluster.clone(), default_policy, detect_timeout);
        Self {
            index,
            cluster,
            detect_timeout,
            default_policy,
            _tracing,
        }
    }
}
