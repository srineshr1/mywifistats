/// Tiny built-in OUI map for common vendors (first 3 octets, lowercase, no separators).
/// Not exhaustive — unknown OUIs simply show no vendor.
pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() < 6 {
        return None;
    }
    let prefix = &hex[..6];
    OUI.iter().find(|(p, _)| *p == prefix).map(|(_, v)| *v)
}

static OUI: &[(&str, &str)] = &[
    ("000c29", "VMware"),
    ("00155d", "Microsoft Hyper-V"),
    ("001a11", "Google"),
    ("001b63", "Apple"),
    ("001e10", "Huawei"),
    ("001f3a", "Hon Hai / Foxconn"),
    ("00259e", "Huawei"),
    ("0050f2", "Microsoft"),
    ("00e04c", "Realtek"),
    ("0c8bfd", "Intel"),
    ("10521c", "Espressif"),
    ("18d6c7", "TP-Link"),
    ("1c697a", "EliteGroup"),
    ("247703", "Intel"),
    ("28c63f", "Intel"),
    ("2c3361", "Apple"),
    ("34243e", "ZTE"),
    ("34e6ad", "Intel"),
    ("3c5ab4", "Google"),
    ("40490f", "Hon Hai"),
    ("48a472", "Intel"),
    ("50284a", "Intel"),
    ("525400", "QEMU/KVM"),
    ("5c514f", "Intel"),
    ("60f677", "Intel"),
    ("70b3d5", "IEEE Registration"),
    ("78fc14", "Family Global"),
    ("7c67a2", "Intel"),
    ("80e650", "Apple"),
    ("88e9fe", "Apple"),
    ("9c5cf9", "Sony"),
    ("a4c361", "Apple"),
    ("acde48", "Private"),
    ("b827eb", "Raspberry Pi"),
    ("b8bc5b", "Samsung"),
    ("bc8335", "Microsoft"),
    ("c83a35", "Tenda"),
    ("d05099", "ASUSTek"),
    ("d83add", "Raspberry Pi"),
    ("dc4427", "IEEE Registration"),
    ("e4b318", "Intel"),
    ("e8ea6a", "StarTech"),
    ("f0d1a9", "Apple"),
    ("f4f5d8", "Google"),
    ("fc3497", "ASUSTek"),
];
