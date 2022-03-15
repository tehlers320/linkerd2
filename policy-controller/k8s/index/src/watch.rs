use crate::{DefaultPolicy, SharedIndex};
use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use futures::prelude::*;
use k8s::ResourceExt;
use linkerd_policy_controller_k8s_api as k8s;
use std::collections::hash_map::Entry;

pub async fn pods(idx: SharedIndex, events: impl Stream<Item = k8s::WatchEvent<k8s::Pod>>) {
    tokio::pin!(events);
    while let Some(ev) = events.next().await {
        match ev {
            k8s::WatchEvent::Applied(pod) => {
                let namespace = pod.namespace().unwrap();
                let name = pod.name();
                let default_policy =
                    DefaultPolicy::from_annotation(&pod.metadata).unwrap_or_else(|error| {
                        tracing::warn!(%error, "invalid default policy annotation value");
                        None
                    });

                let mut idx = idx.write();
                let nsidx = idx.get_ns_or_default(namespace);
                match nsidx.apply_pod(
                    name,
                    pod.metadata.labels.into(),
                    tcp_port_names(pod.spec),
                    default_policy,
                ) {
                    Err(error) => tracing::error!(%error, "Illegal pod update"),
                    Ok(false) => tracing::trace!("pod update ignored"),
                    Ok(true) => nsidx.reindex(),
                }
            }

            k8s::WatchEvent::Deleted(pod) => {
                let namespace = pod.namespace().unwrap();
                let name = pod.name();
                let mut idx = idx.write();
                if let Some(nsidx) = idx.get_ns_mut(&namespace) {
                    if nsidx.delete_pod(&name) {
                        nsidx.reindex();
                    }
                }
            }

            k8s::WatchEvent::Restarted(pods) => {
                let mut idx = idx.write();

                // Iterate through all the pods in the restarted event and add/update them in the
                // index. Keep track of which namespaces need to be reindexed and which pods need to
                // be removed from the index.
                let mut remove_pods = idx.dump_pods();
                let mut reindex_namespaces = HashSet::new();
                for pod in pods.into_iter() {
                    let namespace = pod.namespace().unwrap();
                    let name = pod.name();

                    // If the pod was in the index and is being updated, it doesn't need to be
                    // removed.
                    if let Some(remove_pods) = remove_pods.get_mut(&namespace) {
                        remove_pods.remove(&name);
                    }

                    let default_policy = DefaultPolicy::from_annotation(&pod.metadata)
                        .unwrap_or_else(|error| {
                            tracing::warn!(%error, "invalid default policy annotation value");
                            None
                        });
                    match idx.get_ns_or_default(&namespace).apply_pod(
                        name,
                        pod.metadata.labels.into(),
                        tcp_port_names(pod.spec),
                        default_policy,
                    ) {
                        Err(error) => tracing::error!(%error, "Illegal pod update"),
                        Ok(false) => tracing::trace!("pod update ignored"),
                        Ok(true) => {
                            // If the pod was added or changed, flag the namespace to be reindexed.
                            reindex_namespaces.insert(namespace);
                        }
                    }
                }

                // Iterate through all pods that were in the index but are no longer in the cluster
                // following a restart. Remove them from the index and flag the namespace to be
                // reindexed.
                for (ns, pods) in remove_pods.into_iter() {
                    let nsidx = idx.get_ns_mut(&ns).expect("namespace must exist in index");
                    for pod in pods.into_iter() {
                        if nsidx.delete_pod(&pod) {
                            reindex_namespaces.insert(ns.clone());
                        }
                    }
                }

                // Reindex all namespaces that were affected by the restart.
                for ns in reindex_namespaces.into_iter() {
                    let mut entry = match idx.entry(ns) {
                        Entry::Occupied(entry) => entry,
                        Entry::Vacant(_) => panic!("namespace must exist in index"),
                    };
                    if entry.get().is_empty() {
                        // If there are no more resources in the namespace, remove it.
                        entry.remove();
                    } else {
                        // Othewise, reindex the namespace.
                        entry.get_mut().reindex();
                    }
                }
            }
        }
    }
}

fn tcp_port_names(spec: Option<k8s::PodSpec>) -> HashMap<String, HashSet<u16>> {
    let mut port_names = HashMap::default();
    if let Some(spec) = spec {
        for container in spec.containers.into_iter() {
            if let Some(ports) = container.ports {
                for port in ports.into_iter() {
                    if let None | Some("TCP") = port.protocol.as_deref() {
                        if let Some(name) = port.name {
                            port_names
                                .entry(name)
                                .or_insert_with(HashSet::new)
                                .insert(port.container_port as u16);
                        }
                    }
                }
            }
        }
    }
    port_names
}
