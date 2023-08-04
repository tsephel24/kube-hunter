import sys
import os
import logging
import threading
from kubernetes import client, config

from kube_hunter.conf import Config, get_config
from kube_hunter.core.events.event_handler import handler
from kube_hunter.core.events.types import Vulnerability, Event
from kube_hunter.core.types import Hunter, KubernetesCluster, AccessContainerServiceAccountTechnique, ActiveHunter, GeneralSensitiveInformationTechnique
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent, HostScanEvent

# kube_config = Config()
# get_config(kube_config)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger('rbac-scanner')
kube_hunter_logger = logging.getLogger('kube_hunter')
kube_hunter_logger.setLevel(logging.WARNING)

vulnerabilities_lock = threading.Lock()
vulnerabilities = list()

class OverlyPermissiveAccess(Vulnerability, Event):
    def __init__(self, role, rule):
        Vulnerability.__init__(self, KubernetesCluster, "Overly permissive access", category=AccessContainerServiceAccountTechnique)
        self.role = role
        self.rule = rule
        self.evidence = f"Role: {role}, Rule: {rule}"
        self.location = f"Role: {role}, Rule: {rule}"

class LeastPrivilegeViolation(Vulnerability, Event):
    print("Script has started: 1")
    def __init__(self, subject, rule, resource):
        Vulnerability.__init__(self, KubernetesCluster, "Violation of least privilege", category=AccessContainerServiceAccountTechnique)
        self.subject = subject
        self.rule = rule
        self.resource = resource
        self.evidence = f"Subject: {subject}, Rule: {rule}, Resource: {resource}"

# class RBACEvent(Vulnerability, Event):
#     """Indicates an issue with RBAC configuration that might pose a security risk."""

#     def __init__(self, details):
#         Vulnerability.__init__(
#             self,
#             component=KubernetesCluster,
#             name="RBAC Misconfiguration",
#             category=GeneralSensitiveInformationTechnique,
#             vid="KHV059",  
#         )
#         self.details = details
#         self.evidence = f"RBAC misconfiguration: {self.details}"

class RBACEvent(Event):
    """Event for starting RBAC checks."""
    pass

handler.publish_event(RunningAsPodEvent())
@handler.subscribe(RBACEvent)
class CheckRBACMisconfigurations(ActiveHunter):
    print("Script has started: 2")
    # def __init__(self, event):
    #     self.event = event

    # def execute(self):
    #     config = get_config()
    try:
        print("Script has started: 3")
        logger.info("Starting execution of CheckRBACMisconfigurations")
        config.load_incluster_config()
        v1 = client.RbacAuthorizationV1Api()
        logger.debug("About to list role bindings for all namespaces")
        rolebindings = v1.list_role_binding_for_all_namespaces()

        print("Script has started: 4")
        for rolebinding in rolebindings.items:
            subjects = rolebinding.subjects
            role_name = rolebinding.role_ref.name
            role_kind = rolebinding.role_ref.kind

            role = self.get_role(role_kind, role_name, rolebinding.metadata.namespace)
            for rule in role.rules:
                if "*" in rule.resources or "*" in rule.verbs:
                    vulnerability_event = OverlyPermissiveAccess(role, rule)
                    with vulnerabilities_lock:
                        vulnerabilities.append(vulnerability_event)
                    logger.info(f'Found vulnerability "{vulnerability_event.get_name()}" in {vulnerability_event.location()}')
                else:
                    for subject in subjects:
                        if subject.kind in ["ServiceAccount", "User"]:
                            for resource in rule.resources:
                                if not self.check_access(subject, rule.verbs, resource, rolebinding.metadata.namespace):
                                    vulnerability_event = LeastPrivilegeViolation(subject, rule, resource)
                                    with vulnerabilities_lock:
                                        vulnerabilities.append(vulnerability_event)
                                    logger.info(f'Found vulnerability "{vulnerability_event.get_name()}" in {vulnerability_event.location()}')  
    except Exception as e:
        logger.info("Script has started:5")
        logger.exception("Exception occurred")  # This line is changed

    def get_role(self, role_kind, role_name, namespace):
        config = get_config()
        if role_kind == "Role":
            print("Script has started: 6")
            return client.RbacAuthorizationV1Api().read_namespaced_role(name=role_name, namespace=namespace)
        elif role_kind == "ClusterRole":
            return client.RbacAuthorizationV1Api().read_cluster_role(name=role_name)
        else:
            print("Script has started:7")
            raise ValueError("Unknown role kind")

    def check_access(self, subject, verbs, resource, namespace):
        """Check if a subject has access to a resource using SelfSubjectAccessReview."""
        config = get_config()
        for v in verbs:
            print("Script has started:8")
            ssar = client.AuthorizationV1Api().create_self_subject_access_review(
                body=client.V1SelfSubjectAccessReview(
                    spec=client.V1SelfSubjectAccessReviewSpec(
                        resource_attributes=client.V1ResourceAttributes(
                            group="",
                            resource=resource,
                            verb=v,  # expects a string
                            namespace=namespace
                        )
                    )
                )
            )
            if not ssar.status.allowed:
                return False
        return True

if __name__ == "__main__":
    logger.info("Script has started:9")

    # kube_config = Config()
    config = get_config()

    config.load_incluster_config()

    handler.publish_event(RBACEvent())

    handler.join()

    with vulnerabilities_lock:
        for vulnerability in vulnerabilities:
            logger.info(str(vulnerability))  

