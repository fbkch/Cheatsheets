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
