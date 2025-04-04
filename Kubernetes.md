### Pods
###### <font style="color:#00b3ff">Check Pods </font> 

```
kubectl get pods
```

###### <font style="color:#00b3ff">Create a new Pod with the `nginx` image </font> 

```
kubectl run nginx --image=nginx
```

###### <font style="color:#00b3ff">Get info about a Pod </font> 

```
kubectl describe pod <pod-name>
```

###### <font style="color:#00b3ff">Check on which Node the Pods are running </font> 

```
kubectl get pods -o wide
```
###### <font style="color:#00b3ff">Delete a Pod</font> 

```
kubectl delete pod <pod-name>

kubectl delete --all pods
```
###### <font style="color:#00b3ff">Create a new pod with the name `redis` and the image `redis123`.</font> 

```
kubectl run redis --image=redis123 --dry-run=client -o yaml > redis-definition.yaml

kubectl create -f redis-definition.yaml
```
###### <font style="color:#00b3ff">Change the config of a Pod</font> 

```
kubectl edit pod redis
OR
kubectl apply -f redis-definition.yaml  (use nano before to update the yaml)
```

###### <font style="color:#00b3ff">Generate POD Manifest YAML file (-o yaml). Don’t create it(–dry-run)</font> 
```
kubectl run nginx --image=nginx --dry-run=client -o yaml
```

###### <font style="color:#00b3ff">Get Pod in a specific env or business unit</font> 
```
kubectl get po --selector env=dev
kubectl get po --selector bu=finance
```

###### <font style="color:#00b3ff">Get YAML config of a currently running Pod</font> 
```
kubectl get po mypod -o yaml > mypod.yaml
```
###### <font style="color:#00b3ff">Replace a currently running Pod</font> 
```
kubectl replace -f new-pod.yaml --force
```

###### <font style="color:#00b3ff">Execute command in a container within a Pod</font> 
```
kubectl -n elastic-stack exec -it app -- cat /log/app.log
```

### Nodes
###### <font style="color:#00b3ff">Check Nodes </font> 

```
kubectl get nodes
```

###### <font style="color:#00b3ff">Create a specific taint on a node</font> 

```
kubectl taint nodes node01 spray=mortein:NoSchedule
```

###### <font style="color:#00b3ff">Remove a specific taint on a node</font> 

```
kubectl taint nodes controlplane node-role.kubernetes.io/control-plane:NoSchedule-
```

###### <font style="color:#00b3ff">Empty a node for maintenance </font> 

```
kubectl drain node01 --ignore-daemonsets
```

###### <font style="color:#00b3ff">Make the node not schedulable</font> 

```
kubectl cordon node01
```
###### <font style="color:#00b3ff">Make the node schedulable again</font> 

```
kubectl uncordon node01
```

### ReplicaSets
###### <font style="color:#00b3ff">Check ReplicaSets </font> 

```
kubectl get rs

kubectl describe replicaset
```

###### <font style="color:#00b3ff">Create ReplicaSet </font> 

```
kubectl create -f /root/replicaset-definition-1.yaml

kubectl apply -f /root/replicaset-definition-2.yaml
```

###### <font style="color:#00b3ff">Scale a ReplicaSet to 5 Pods</font> 

```
kubectl scale replicaset new-replica-set --replicas=5
```

### Deployments
###### <font style="color:#00b3ff">Get information about all </font> 

```
kubectl get all
```
###### <font style="color:#00b3ff">Create a deployment </font> 

```
kubectl create deployment --image=nginx nginx
```
###### <font style="color:#00b3ff">Generate Deployment YAML file </font> 

```
kubectl create deployment --image=nginx nginx --dry-run=client -o yaml > nginx-deployment.yaml
```
###### <font style="color:#00b3ff">Get documentation explanation about Deployment </font> 

```
kubectl explain deployment
```

###### <font style="color:#00b3ff">Create a Deployment with 3 replicas</font> 

```
kubectl create deployment  webapp --image=kodekloud/webapp-color --replicas=3
```

### Services
###### <font style="color:#00b3ff">Get information about services </font> 

```
kubectl get services
```

###### <font style="color:#00b3ff">Describe services </font> 

```
kubectl describe services
```

###### <font style="color:#00b3ff">Create a service to expose the pod redis on port 6379 </font> 

```
kubectl expose pod redis --port=6379 --name redis-service
```


### Namespaces
###### <font style="color:#00b3ff">Get information namespaces </font> 

```
kubectl get namespace
kubectl get ns
```

###### <font style="color:#00b3ff">Get Pods from a specific namespace </font> 

```
kubectl get pods --namespace=test
```

###### <font style="color:#00b3ff">Create a Pod in a namespace </font> 

```
kubectl run redis --image=redis -n test
```

###### <font style="color:#00b3ff">List Pods in all namespaces </font> 

```
kubectl get pods --all-namespaces
```

###### <font style="color:#00b3ff">Create a namespaces </font> 

```
kubectl create ns dev-ns
```

### Scheduling
###### <font style="color:#00b3ff">Get information about system-level pods </font> 

```
kubectl get pods --namespace kube-system
```


### DaemonSets
###### <font style="color:#00b3ff">Get daemonsets in all namespaces </font> 

```
kubectl get daemonsets --all-namespaces
```

###### <font style="color:#00b3ff">Create a daemonSet </font> 

```
kubectl create deployment elasticsearch --image=registry.k8s.io/fluentd-elasticsearch:1.20 -n kube-system --dry-run=client -o yaml > fluentd.yaml

-> remove the replicas, strategy and status fields from the YAML file using a text editor. Also, change the kind from `Deployment` to `DaemonSet`
```

### Etcd
###### <font style="color:#00b3ff">Get Etcd version, info </font> 

```
kubectl -n kube-system logs etcd-controlplane | grep -i 'etcd-version'

kubectl -n kube-system describe pod etcd-cluster1-controlplane
```

###### <font style="color:#00b3ff">Take Etcd snapshot </font> 

```
ETCDCTL_API=3 etcdctl --endpoints=https://[127.0.0.1]:2379 \
--cacert=/etc/kubernetes/pki/etcd/ca.crt \
--cert=/etc/kubernetes/pki/etcd/server.crt \
--key=/etc/kubernetes/pki/etcd/server.key \
snapshot save /opt/snapshot-pre-boot.db
```

###### <font style="color:#00b3ff">Restore Etcd snapshot </font> 

```
ETCDCTL_API=3 etcdctl  --data-dir /var/lib/etcd-from-backup \
snapshot restore /opt/snapshot-pre-boot.db
```

### Cluster
###### <font style="color:#00b3ff">View the different clusters </font> 

```
kubectl config view
```

###### <font style="color:#00b3ff">Switch context to one of the cluster </font> 

```
kubectl config use-context cluster1
```

### TLS
###### <font style="color:#00b3ff">Identify the certificate file used for the kube-api server </font> 

```
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep tls-cert-file
```

###### <font style="color:#00b3ff">Red info from the kube-api server certificate</font> 

```
openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text
```

### Kubeconfig
###### <font style="color:#00b3ff">Get the kubeconfig from a specific configuration file </font> 

```
kubectl config view --kubeconfig my-kube-config
```

###### <font style="color:#00b3ff">Get the current context </font> 

```
kubectl config --kubeconfig=/root/my-kube-config current-context
```

###### <font style="color:#00b3ff">Set the current context </font> 

```
kubectl config --kubeconfig=/root/my-kube-config use-context research
```

### RBAC
###### <font style="color:#00b3ff">Get roles in all namespaces </font> 

```
kubectl get roles -A
```

###### <font style="color:#00b3ff">Create a role</font> 

```
kubectl create role developer --namespace=default --verb=list,create,delete --resource=pods
```
###### <font style="color:#00b3ff">Assign a role</font> 

```
kubectl create rolebinding dev-user-binding --namespace=default --role=developer --user=dev-user
```

###### <font style="color:#00b3ff">Edit a role in a specific namespace</font> 

```
kubectl edit role developer -n blue
```

###### <font style="color:#00b3ff">Get and count cluster roles</font> 

```
kubectl get clusterroles --no-headers | wc -l
```

###### <font style="color:#00b3ff">Check if a resource is not namespaced</font> 

```
kubectl api-resources --namespaced=false
```

###### <font style="color:#00b3ff">Test if a user can perform an action</font> 

```
kubectl auth can-i list nodes --as michelle
```

### Service Accounts
###### <font style="color:#00b3ff">Set the service account in a deployment </font> 

```
kubectl set serviceaccount deploy/web-dashboard dashboard-sa 
```


### Network Policies
###### <font style="color:#00b3ff">Get the network policies </font> 

```
kubectl get networkpolicy
```

###### <font style="color:#00b3ff">Get IP range for the services in the cluster</font> 

```
cat /etc/kubernetes/manifests/kube-apiserver.yaml   | grep cluster-ip-range
```

###### <font style="color:#00b3ff">Check logs of a kube-proxy pod</font> 

```
kubectl logs <kube-proxy-pod-name> -n kube-system
```


### Persistent Volume Claims
###### <font style="color:#00b3ff">Get the Persistent Volume Claims and Persistent Volume </font> 

```
kubectl get pv,pvc
```

### CNI
###### <font style="color:#00b3ff">Identify the container runtime endpoint</font> 

```
ps -aux | grep kubelet | grep --color container-runtime-endpoint
```

### Ingress
###### <font style="color:#00b3ff">Check the config in the Ingress</font> 

```
kubectl describe ingress --namespace app-space

If default:
kubectl get deploy ingress-nginx-controller -n ingress-nginx -o yaml
```


### Additional Notes to prepare the CKA

- exec command (liveness probe) sh -c “wget …”
- get pod -A
- export do=“—dry-run=client -o yaml”
- k -n namespaces blabla …
- grep -i A2
- vi: :%s/test/test2/g
- Questions with .sh, put full command with **kubectl**
- k top
- CNI: cat /etc/cni/net.d/10-weave.conflist
- Service CIDR: cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep range
- Static pod suffix: node -hostname
- VIM: visual mode V, select the Y, then paste P
- Delete specific container in a pod: ssh then crictl rm 1e020b43c4423
- Remote instruction: ssh cluster1-node2 'crictl logs b01edbe6f89ed' **&>** /opt/course/17/pod-container.log
- apt show kubelet -a | grep 1.31
- use labels to find resources:      k get svc,ep -l run=my-static-pod
- —sort-by=.metadata  (dont forget the dot . in front)
- emptyDir (temp shared volume in a pod)
- Node joining full command:      kubeadm token create --print-join-command
- Apply use-context cmd in every terminal
- Can curl a pod with its IP (-o wide) even without an SVC
- Networkpolicy: -to for each rule
- Kubernetes HTTP API as an SVC: [https://kurbenetes.default/api/v1/[object]](https://kurbenetes.default/api/v1/%5Bobject%5D) (curl -k)
- k exec mypod -it — sh
- crictl exec  -it dddwe sh
- iptables-save
- Change cluster ip range: kube-apiserver + kube-controller
- **k explain ingress.spec --recursive** // Use this to explain any resources and get the fields faster
- k get events --field-selector "involvedObject.name=webpage-server-02"
- k get events -o yaml
- Use --sort-by=.blabla.blabla  when sorting output
- OOMKilled on a pod is memory issue, increase limits.memory
- HTTProute spec.rules.MATCH.backendRefs.weight 
- Sidecar is just another container (no need to create an initContainer)
- HTTProute specify the namespace of the parent class if needed. For the rules do multiple matches
- Ingress: ssl-redirect in annotations
- k get po -o json | jq -c 'paths|map(tostring)|join(".")'   // useful cmd to get the path for the jsonpath
- when using curl to test an svc, specify the svc port
- Using Range and \n:      k -n project-c13 get pod -o jsonpath="{range .items[*]} {.metadata.name}{.spec.containers[*].resources}{'\n'}"
- curl -k [https://kubernetes.default/api/v1/secrets](https://kubernetes.default/api/v1/secrets)
- apt show kubelet -a , apt install kubelet=1.3.2-blabla
- crictl rm —force
- nodeSelector, fieldref