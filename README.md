<h2>Certified Kubernetes Security Specialist (CKS) Course</h2>

- [Certified Kubernetes Security Specialist (CKS) Exam Curriculum](#certified-kubernetes-security-specialist-cks-exam-curriculum)
- [Understanding the Kubernetes Attack Surface](#understanding-the-kubernetes-attack-surface)
  - [The Attack](#the-attack)
  - [The 4C’s of Cloud Native security](#the-4cs-of-cloud-native-security)
- [Cluster Setup and Hardening](#cluster-setup-and-hardening)
  - [What are CIS Benchmarks?](#what-are-cis-benchmarks)
  - [Kube-bench](#kube-bench)
  - [Kubernetes Security Primitives](#kubernetes-security-primitives)
  - [Kubernetes Cluster Authentication](#kubernetes-cluster-authentication)
    - [Static File](#static-file)
    - [Static Token](#static-token)
  - [Service Account](#service-account)
  - [TLS Basic](#tls-basic)
    - [TLS in Kubernetes](#tls-in-kubernetes)
  - [Authorization Modes](#authorization-modes)
  - [Why Securing Kubelet API is Critical for K8s Security?](#why-securing-kubelet-api-is-critical-for-k8s-security)
- [Seccomp](#seccomp)
- [AppArmor](#apparmor)
- [Admission Controllers](#admission-controllers)
- [Validating and Mutating Admission Controllers](#validating-and-mutating-admission-controllers)



## Certified Kubernetes Security Specialist (CKS) Exam Curriculum

**10% - Cluster Setup**
• Use Network security policies to restrict cluster level access
• Use CIS benchmark to review the security configuration of Kubernetes components
(etcd, kubelet, kubedns, kubeapi)
• Properly set up Ingress objects with security control
• Protect node metadata and endpoints
• Minimize use of, and access to, GUI elements
• Verify platform binaries before deploying

**15% - Cluster Hardening**
• Restrict access to Kubernetes API
• Use Role Based Access Controls to minimize exposure
• Exercise caution in using service accounts e.g. disable defaults, minimize permissions on
newly created ones
• Update Kubernetes frequently

**15% - System Hardening**
• Minimize host OS footprint (reduce attack surface)
• Minimize IAM roles
• Minimize external access to the network
• Appropriately use kernel hardening tools such as AppArmor, seccomp

**20% - Minimize Microservice Vulnerabilities**
• Setup appropriate OS level security domains
• Manage kubernetes secrets
• Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)
• Implement pod to pod encryption by use of mTLS

**20% - Supply Chain Security**
• Minimize base image footprint
• Secure your supply chain: whitelist allowed image registries, sign and validate images
• Use static analysis of user workloads (e.g. kubernetes resources, docker files)
• Scan images for known vulnerabilities

**20% - Monitoring, Logging and Runtime Security**
• Perform behavioral analytics of syscall process and file activities at the host and container
level to detect malicious activities
• Detect threats within physical infrastructure, apps, networks, data, users and workloads
• Detect all phases of attack regardless where it occurs and how it spreads
• Perform deep analytical investigation and identification of bad actors within environment
• Ensure immutability of containers at runtime
• Use Audit Logs to monitor access



## Understanding the Kubernetes Attack Surface


### The Attack


### The 4C’s of Cloud Native security
The 4C's of Cloud Native security represent a framework for understanding and implementing security practices within cloud-native environments. These principles are essential for ensuring the security, reliability, and resilience of applications and services deployed in cloud-native architectures. The 4C's are:

**1. Cloud Security:**
Data Protection: Ensure sensitive data is encrypted both in transit and at rest. Utilize encryption mechanisms provided by the cloud service provider.
Identity and Access Management (IAM): Implement robust identity and access controls to manage user permissions and prevent unauthorized access.
Compliance: Adhere to relevant compliance standards and regulations to maintain data integrity and protect against legal and regulatory risks.
Cloud Provider Security Features: Leverage built-in security features and services provided by the cloud service provider, such as AWS Security Groups, Azure Security Center, or Google Cloud IAM.

**2. Cluster Security:**
Network Security: Implement network segmentation, firewall rules, and network policies to control traffic flow and secure communication between cluster components.
Authentication and Authorization: Configure authentication mechanisms and role-based access control (RBAC) to authenticate users and authorize access to cluster resources.
Monitoring and Logging: Set up monitoring and logging solutions to track cluster activity, detect security incidents, and facilitate incident response and forensic analysis.
Resource Hardening: Harden cluster nodes and control plane components by applying security best practices, disabling unnecessary services, and regularly patching and updating software.

**3. Container Security:**
Image Scanning: Scan container images for vulnerabilities and malware before deployment to prevent security breaches.
Runtime Protection: Implement runtime security controls to monitor container behavior, detect anomalies, and prevent unauthorized access or malicious activities.
Immutable Infrastructure: Use immutable infrastructure patterns to minimize security risks by replacing containers rather than patching or updating them in place.
Isolation: Utilize container isolation mechanisms, such as namespaces and cgroups, to enforce separation between containers and prevent container escape attacks.

**4. Code Security:**
Secure Coding Practices: Follow secure coding practices to mitigate common vulnerabilities, such as injection attacks, cross-site scripting (XSS), and insecure deserialization.
Static and Dynamic Analysis: Conduct static and dynamic code analysis to identify security flaws, vulnerabilities, and potential security weaknesses in application code.
Dependency Management: Regularly update dependencies and libraries to patch security vulnerabilities and ensure the integrity and security of third-party code.
Secure DevOps Pipeline: Integrate security into the DevOps pipeline by incorporating security testing, code review, and automated security scanning into the development and deployment process.


## Cluster Setup and Hardening

### What are CIS Benchmarks?
CIS (Center for Internet Security) Benchmarks are industry-standard best practices for securely configuring technology platforms. Developed by the Center for Internet Security, they offer consensus-based guidelines aligned with industry standards to enhance cybersecurity posture and reduce risk. These benchmarks cover a wide range of systems, provide scoring guides, and are continuously updated to address emerging threats.


### Kube-bench


### Kubernetes Security Primitives


### Kubernetes Cluster Authentication

#### Static File

#### Static Token

### Service Account

### TLS Basic

#### TLS in Kubernetes

In Kubernetes, the responsibility for generating TLS certificates varies depending on the component. Here's a breakdown:

1. **API Server**:
   - The API server typically generates its own TLS certificate, often during the initialization of the Kubernetes cluster. This certificate is used to secure communication with clients (kubelet, controllers, kubectl) and can be configured to have a specific Common Name (CN) or Subject Alternative Name (SAN) to match the server's identity.

2. **etcd**:
   - Consistent and highly-available key value store used as Kubernetes' backing store for all cluster data
   - Similar to the API server, etcd can generate its own TLS certificates during initialization or configuration. These certificates are used to secure communication between etcd nodes and other components like the API server. Each etcd node may have its own TLS certificate.

3. **Controller Manager** and **Scheduler**:
   - These components typically do not generate their own TLS certificates by default. They may utilize certificates provided by the cluster administrator or generated as part of the cluster initialization process. If required, they can be configured to use TLS certificates for secure communication with other components.

4. **Kubelet** and **kube-proxy**:
   - This command line interface is used to communicate with your Kubernetes cluster and issue commands.
   - Each kubelet and kube-proxy instance can generate its own TLS certificate or use certificates provided by the cluster administrator. These certificates are used to secure communication with the API server and other components, ensuring that the communication channels are encrypted and authenticated.

5. **Service-to-Service Communication**:
   - Services within the cluster may or may not generate their own TLS certificates. If TLS is enabled for service communication, certificates may be provided by the cluster administrator or generated by the services themselves. It depends on the specific requirements and configurations of the cluster.

6. **Ingress Controller**:
   - Ingress controllers may generate their own TLS certificates for terminating TLS connections from external clients. These certificates are used to secure the communication between external clients and the services within the cluster. Alternatively, certificates may be provided by the cluster administrator or obtained from a trusted certificate authority.

**Certificate Authority**

```bash
openssl genrsa -out ca.key 2048
openssl req -new -key ca.key -out ca.csr -subj "/CN=KUBERNETES-CA"
openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt -days 365
```

**For Admin user, Differentiate via O=system:masters**

```bash
openssl genrsa -out admin.key 2048
openssl req -new -key admin.key -out admin.csr -subj "/CN=admin/O=system:masters"
openssl x509 -req -in admin.csr -CA ca.crt -CAkey ca.key -out admin.crt -days 365

```


`openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text -noout`


### Authorization Modes
Authorization Modes
In Kubernetes, authorization modes determine how access control decisions are made. The authorization mode specifies the mechanism by which the Kubernetes API server determines whether a request to access a resource should be allowed or denied. There are several authorization modes available, each with its own way of making these decisions. The main authorization modes in Kubernetes are:

Node:
In Node authorization mode, the kubelet (Kubernetes node agent) authorizes API requests on behalf of the node.
This mode is typically used in clusters where kubelet has sufficient permissions to access the API server directly.
It's commonly used in small, single-tenant clusters or in situations where authentication is managed outside of Kubernetes.

RBAC (Role-Based Access Control):
RBAC authorization mode is the most commonly used mode in Kubernetes.
It allows administrators to define roles that specify a set of permissions and bind those roles to users, groups, or service accounts.
RBAC enables fine-grained access control by defining who can perform which actions on which resources within a namespace or cluster-wide.

Webhook:
In Webhook authorization mode, the kube-apiserver defers authorization decisions to an external webhook service.
When a request is made to the API server, it sends the request data to the webhook service, which then makes the authorization decision based on its own logic.
This mode allows for custom authorization logic to be implemented outside of Kubernetes.

ABAC (Attribute-Based Access Control):
ABAC authorization mode allows administrators to specify policies based on attributes of the request, such as the user's identity, group memberships, or other request metadata.
While ABAC provides flexibility, it's less commonly used than RBAC due to its complexity and potential security risks.

AlwaysDeny:
In AlwaysDeny authorization mode, all requests to the API server are denied, regardless of the user's identity or the requested action.
This mode is typically used for testing or debugging purposes and should not be used in production environments.
By default, Kubernetes uses RBAC authorization mode. However, administrators can configure the authorization mode to suit the security requirements and operational needs of their clusters. The choice of authorization mode depends on factors such as the cluster's security requirements, the complexity of access control policies, and the level of control required over access to Kubernetes resources.


`kubectl auth can-i list nodes --as michelle`



### Why Securing Kubelet API is Critical for K8s Security?

Get the token of admin-user and login into UI. Check whether you can modify any of resources Get token by running below and login to UI with that token

`kubectl get secrets -n kubernetes-dashboard admin-user -o go-template="{{.data.token | base64decode}}"`

characters of the shasum of previously downloaded file

`shasum -a512 kubernetes.tar.gz`


## Seccomp
Seccomp is a powerful security feature in Linux that restricts the system calls a process can make, enhancing overall system security. Here's a concise summary:

Definition: Seccomp, short for "secure computing mode," is a Linux kernel feature that restricts the system calls available to a process. It provides a sandbox environment for processes, limiting their ability to interact with the kernel.
Functionality: Seccomp filters system calls, allowing only a defined subset to be executed by a process. This reduces the attack surface by restricting access to potentially dangerous system functions.
Policy Creation: Seccomp policies specify which system calls are permitted and which are denied. Policies are typically defined using BPF (Berkeley Packet Filter) programs, offering fine-grained control over syscall filtering.
Enforcement: The Linux kernel enforces Seccomp policies, intercepting system calls made by processes and comparing them against the defined policy. If a prohibited syscall is attempted, it is blocked, preventing potential security threats.
Use Cases:
Sandboxing: Seccomp is commonly used to isolate and sandbox untrusted processes, such as those running in containers or web browsers, reducing their attack surface.
Security Hardening: It helps mitigate the impact of security vulnerabilities by limiting the capabilities of processes and thwarting exploit attempts.
Advantages:
Enhanced Security: By restricting access to system calls, Seccomp reduces the risk of privilege escalation and limits the impact of security breaches.
Performance: Seccomp filtering is lightweight and has minimal performance overhead, making it suitable for use in production environments.
Community Support: Seccomp is actively maintained and supported by the Linux kernel community, ensuring ongoing development and improvement.
In summary, Seccomp provides a robust mechanism for restricting system call access in Linux, enhancing security by reducing attack surface and mitigating the impact of security vulnerabilities. Its flexibility and performance make it a valuable tool for securing diverse computing environments

## AppArmor
AppArmor is a robust security framework for Linux systems, offering granular control over program capabilities to enhance system security. Here's a brief summary:

Purpose: AppArmor is designed to confine individual programs within predefined security policies, limiting their access to system resources and actions.
Mechanism: It operates by creating security profiles for each application, specifying allowed resources and actions. These policies are enforced by the Linux kernel, which monitors program behavior.
Policy Creation: Security policies are typically written in easy-to-understand text files, making them accessible to users of varying technical backgrounds.
Enforcement: The kernel enforces these policies by blocking any attempts by the application to access restricted resources or perform prohibited actions.
Advantages:
Ease of Use: AppArmor's straightforward policy language makes it user-friendly, even for those without extensive security knowledge.
Integration: It seamlessly integrates with popular Linux distributions like Ubuntu, enhancing the security of system services and applications.
Application: AppArmor finds wide use in securing critical system components, network services, and user applications in Linux environments.
Benefits: By confining program capabilities, AppArmor helps prevent unauthorized access, mitigate the impact of security breaches, and safeguard sensitive data.
Community Support: AppArmor benefits from an active community of users and developers, ensuring ongoing development, support, and improvement.

## Admission Controllers

`ps -ef | grep kube-apiserver | grep admission-plugins`

## Validating and Mutating Admission Controllers
