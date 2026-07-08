//! Well-known port → service-name lookup. Pure data + two functions, so the
//! collector can annotate each socket with a friendly hint (e.g. 5432 →
//! "PostgreSQL"). `lookup` is the raw port-number guess; `lookup_verified`
//! only returns the name when the owning process actually looks like that
//! service, so the label is shown only for services that are really running.

/// Return the conventional service name for a well-known port, if any.
///
/// Covers the ports a software developer most commonly cares about — system
/// services plus the usual dev-server / database / cache / broker ports.
pub fn lookup(port: u16) -> Option<&'static str> {
    let name = match port {
        // ── Core system / network ──────────────────────────────────────────
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 => "TFTP",
        80 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        111 => "rpcbind",
        123 => "NTP",
        137..=139 => "NetBIOS",
        143 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        514 => "Syslog",
        515 => "LPD/Printer",
        587 => "SMTP (submission)",
        631 => "IPP/CUPS",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",

        // ── macOS / Bonjour / Apple ────────────────────────────────────────
        548 => "AFP",
        5353 => "mDNS/Bonjour",
        7000 => "AirPlay",
        62078 => "iPhone sync (usbmuxd)",

        // ── Databases ──────────────────────────────────────────────────────
        1433 => "MS SQL Server",
        1521 => "Oracle DB",
        3306 => "MySQL/MariaDB",
        5432 => "PostgreSQL",
        5984 => "CouchDB",
        6379 => "Redis",
        7001 => "Cassandra",
        7199 => "Cassandra JMX",
        8086 => "InfluxDB",
        9042 => "Cassandra CQL",
        9200 | 9300 => "Elasticsearch",
        11211 => "Memcached",
        27017..=27019 => "MongoDB",

        // ── Message brokers / streaming ────────────────────────────────────
        1883 => "MQTT",
        4222 => "NATS",
        5672 => "AMQP/RabbitMQ",
        9092 => "Kafka",
        15672 => "RabbitMQ mgmt",
        2181 => "ZooKeeper",

        // ── Dev servers / app frameworks ───────────────────────────────────
        1313 => "Hugo dev",
        3000 => "Dev server (Node/Rails)",
        3001 => "Dev server (alt)",
        4000 => "Dev server (Phoenix/Jekyll)",
        4200 => "Angular dev",
        5000 => "Dev server (Flask/.NET)",
        5173 => "Vite dev",
        8000 => "Dev server (Django/HTTP)",
        8080 => "HTTP alt / dev",
        8081 => "HTTP alt",
        8443 => "HTTPS alt",
        8888 => "Jupyter / HTTP alt",
        9000 => "Dev server / SonarQube",
        9229 => "Node.js debugger",

        // ── DevOps / infra / observability ─────────────────────────────────
        2375 | 2376 => "Docker daemon",
        2379 | 2380 => "etcd",
        3030 => "Dev server (alt)",
        3100 => "Loki",
        3200 => "Tempo",
        4317 | 4318 => "OpenTelemetry (OTLP)",
        6443 => "Kubernetes API",
        9090 => "Prometheus",
        9091 => "Prometheus pushgateway",
        9100 => "Prometheus node_exporter",
        9093 => "Alertmanager",
        16686 => "Jaeger UI",

        // ── Remote access / misc ───────────────────────────────────────────
        3389 => "RDP",
        5900 => "VNC",
        5901 => "VNC :1",
        6000 => "X11",
        1080 => "SOCKS proxy",
        3128 => "Squid proxy",

        _ => return None,
    };
    Some(name)
}

/// Lower-case substrings that identify the process(es) conventionally behind
/// each well-known port, matched against the lower-cased process name and
/// command line. An empty slice means the port has no service entry.
fn expected_processes(port: u16) -> &'static [&'static str] {
    match port {
        // ── Core system / network ──────────────────────────────────────────
        20 | 21 => &["ftpd"],
        22 => &["sshd"],
        23 => &["telnetd"],
        25 | 465 | 587 => &["smtpd", "postfix", "sendmail", "exim", "opensmtpd"],
        53 => &[
            "named",
            "dnsmasq",
            "unbound",
            "coredns",
            "systemd-resolve",
            "mdnsresponder",
        ],
        67 | 68 => &["dhcpd", "dhclient", "udhcp", "configd", "dnsmasq"],
        69 => &["tftpd"],
        80 | 8081 => &[
            "nginx", "httpd", "apache", "caddy", "traefik", "haproxy", "envoy",
        ],
        88 => &["kdc", "kerberos"],
        110 | 995 => &["dovecot", "popd"],
        111 => &["rpcbind"],
        123 => &["ntpd", "chronyd", "timed", "timesync", "ntpsec"],
        137..=139 | 445 => &["smbd", "nmbd", "samba", "netbiosd"],
        143 | 993 => &["dovecot", "imapd"],
        161 | 162 => &["snmpd"],
        389 | 636 => &["slapd", "ldap"],
        443 | 8443 => &[
            "nginx", "httpd", "apache", "caddy", "traefik", "haproxy", "envoy",
        ],
        514 => &["syslog"],
        515 => &["lpd", "cupsd"],
        631 => &["cupsd"],

        // ── macOS / Bonjour / Apple ────────────────────────────────────────
        548 => &["afpd", "netatalk"],
        5353 => &["mdnsresponder", "avahi"],
        7000 => &["airplay", "controlcenter"],
        62078 => &["usbmux", "remotepairingd", "lockdownd"],

        // ── Databases ──────────────────────────────────────────────────────
        1433 => &["sqlservr"],
        1521 => &["tnslsnr", "oracle"],
        3306 => &["mysqld", "mariadbd"],
        5432 => &["postgres"],
        5984 => &["couchdb"],
        6379 => &["redis"],
        7001 | 7199 | 9042 => &["cassandra"],
        8086 => &["influxd"],
        9200 | 9300 => &["elasticsearch", "opensearch"],
        11211 => &["memcached"],
        27017..=27019 => &["mongod", "mongos"],

        // ── Message brokers / streaming ────────────────────────────────────
        1883 => &["mosquitto", "mqtt", "emqx", "hivemq"],
        4222 => &["nats"],
        5672 | 15672 => &["rabbitmq", "beam"],
        9092 => &["kafka"],
        2181 => &["zookeeper", "zkserver"],

        // ── Dev servers / app frameworks ───────────────────────────────────
        1313 => &["hugo"],
        3000 | 3001 | 3030 => &["node", "bun", "deno", "ruby", "rails", "puma"],
        4000 => &["beam", "elixir", "ruby", "jekyll", "node", "bun"],
        4200 => &["node", "bun"],
        5000 => &["python", "flask", "gunicorn", "uvicorn", "dotnet"],
        5173 => &["node", "vite", "bun", "deno"],
        8000 => &["python", "gunicorn", "uvicorn", "daphne", "node", "php"],
        8080 => &[
            "nginx", "httpd", "apache", "caddy", "traefik", "java", "node", "python",
        ],
        8888 => &["jupyter", "python"],
        9000 => &["sonar", "java", "node", "php-fpm", "python"],
        9229 => &["node", "bun", "deno"],

        // ── DevOps / infra / observability ─────────────────────────────────
        2375 | 2376 => &["docker"],
        2379 | 2380 => &["etcd"],
        3100 => &["loki"],
        3200 => &["tempo"],
        4317 | 4318 => &["otelcol", "otel", "opentelemetry"],
        6443 => &["kube", "k3s", "k8s"],
        9090 => &["prometheus"],
        9091 => &["pushgateway", "prometheus"],
        9100 => &["node_exporter"],
        9093 => &["alertmanager"],
        16686 => &["jaeger"],

        // ── Remote access / misc ───────────────────────────────────────────
        3389 => &["xrdp", "rdp"],
        5900 | 5901 => &["vnc", "screensharing"],
        6000 => &["xorg", "xquartz", "x11"],
        1080 => &["socks", "dante", "ssh"],
        3128 => &["squid"],

        _ => &[],
    }
}

/// Return the service name for a well-known port only when the owning process
/// looks like that service actually running (its name or command line matches
/// one of the expected process keywords). With no process information there is
/// nothing to verify, so nothing is shown.
pub fn lookup_verified(
    port: u16,
    process_name: Option<&str>,
    cmdline: Option<&str>,
) -> Option<&'static str> {
    let name = lookup(port)?;
    let haystack =
        format!("{} {}", process_name.unwrap_or(""), cmdline.unwrap_or("")).to_lowercase();
    if haystack.trim().is_empty() {
        return None;
    }
    expected_processes(port)
        .iter()
        .any(|kw| haystack.contains(kw))
        .then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ports_resolve() {
        assert_eq!(lookup(22), Some("SSH"));
        assert_eq!(lookup(443), Some("HTTPS"));
        assert_eq!(lookup(5432), Some("PostgreSQL"));
        assert_eq!(lookup(6379), Some("Redis"));
        assert_eq!(lookup(5353), Some("mDNS/Bonjour"));
        assert_eq!(lookup(5173), Some("Vite dev"));
    }

    #[test]
    fn unknown_port_is_none() {
        assert_eq!(lookup(49231), None);
    }

    #[test]
    fn verified_when_process_matches() {
        assert_eq!(
            lookup_verified(5432, Some("postgres"), None),
            Some("PostgreSQL")
        );
        assert_eq!(
            lookup_verified(6379, Some("redis-server"), Some("redis-server *:6379")),
            Some("Redis")
        );
        // Match via cmdline even when the process name alone is generic.
        assert_eq!(
            lookup_verified(9092, Some("java"), Some("java -cp ... kafka.Kafka config")),
            Some("Kafka")
        );
    }

    #[test]
    fn hidden_when_process_does_not_match() {
        // A Node app squatting on the PostgreSQL port is not PostgreSQL.
        assert_eq!(
            lookup_verified(5432, Some("node"), Some("node server.js")),
            None
        );
        // macOS ControlCenter on 5000 is not a Flask dev server.
        assert_eq!(lookup_verified(5000, Some("ControlCenter"), None), None);
    }

    #[test]
    fn hidden_when_no_process_info() {
        assert_eq!(lookup_verified(5432, None, None), None);
        assert_eq!(lookup_verified(443, Some(""), Some("")), None);
    }
}
