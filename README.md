# DevSecOps Assessment: Track 1, Kubernetes & Container Security

Work in progress. The executive summary and the module map are filled in as each module lands.

## Reference repositories

| Role | Repository | Pinned commit |
|---|---|---|
| Primary review target | [madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat) | `723a0db478f050d173d23b4ce5044b65bce0bdd0` |
| Supplementary (EKS / ECR Terraform) | [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat) `terraform/aws/eks.tf`, `ecr.tf` | `729f8da62c6a85ce4af5ad3d123de97776d954c4` |
| "What good looks like" baseline | [aws-ia/terraform-aws-eks-blueprints](https://github.com/aws-ia/terraform-aws-eks-blueprints) | referenced, not reviewed |

Every finding cites `path:line` at the pinned commit, so the evidence stays reproducible even if upstream changes.
