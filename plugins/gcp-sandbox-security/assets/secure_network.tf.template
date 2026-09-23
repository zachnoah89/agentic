# Egress control for the default VPC network (HTTP/HTTPS Only)

# 1. Deny all outbound egress from the default network
resource "google_compute_firewall" "deny_all_egress" {
  name    = "deny-all-egress"
  network = "default"
  project = var.gcp_project_id

  direction = "EGRESS"
  priority  = 1000
  
  deny {
    protocol = "all"
  }
  
  destination_ranges = ["0.0.0.0/0"]
}

# 2. Allow egress ONLY for HTTP (80), HTTPS (443), DNS (53), and NTP (123)
resource "google_compute_firewall" "allow_http_https_dns_egress" {
  name    = "allow-http-https-dns-egress"
  network = "default"
  project = var.gcp_project_id

  direction = "EGRESS"
  priority  = 900
  
  allow {
    protocol = "tcp"
    ports    = ["80", "443", "53"]
  }

  allow {
    protocol = "udp"
    ports    = ["53", "123"]
  }
  
  destination_ranges = ["0.0.0.0/0"]
}
