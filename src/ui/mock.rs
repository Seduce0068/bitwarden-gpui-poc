//! Mock vault data used when no credentials are entered.

use crate::model::{
    CardData, Folder, IdentityData, ItemData, LoginUri, SshKeyData, Vault, VaultItem,
};
use zeroize::Zeroizing;

/// A small personal vault used until real sync is wired up.
pub(super) fn mock_vault() -> Vault {
    fn login(
        id: &str,
        name: &str,
        username: &str,
        password: &str,
        uri: &str,
        totp: &str,
    ) -> VaultItem {
        VaultItem::new(
            id,
            name,
            ItemData::Login {
                username: username.to_string(),
                password: Zeroizing::new(password.to_string()),
                totp: Zeroizing::new(totp.to_string()),
                uris: vec![LoginUri::new(uri)],
            },
        )
    }

    let mut vault = Vault::new();
    vault.folders.push(Folder {
        id: "work".into(),
        name: "仕事".into(),
    });

    let mut github = login(
        "1",
        "GitHub",
        "alice@example.com",
        "hunter2",
        "https://github.com/login",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    );
    github.folder_id = Some("work".into());
    github.favorite = true;
    github.revision_date = 1_700_000_100;

    let mut vaultwarden = login(
        "2",
        "Vaultwarden",
        "alice",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://vault.example.com",
        "",
    );
    vaultwarden.folder_id = Some("work".into());
    vaultwarden.revision_date = 1_700_000_200;

    let mut mail = login(
        "3",
        "Email",
        "alice@example.com",
        "1234",
        "http://mail.example.com",
        "",
    );
    mail.revision_date = 1_600_000_000;

    let mut note = VaultItem::new(
        "4",
        "Wi-Fi",
        ItemData::SecureNote {
            text: "guest / guest".into(),
        },
    );
    note.revision_date = 1_700_000_300;

    let mut card = VaultItem::new(
        "5",
        "Visa",
        ItemData::Card(CardData {
            cardholder_name: "Alice Example".into(),
            brand: "Visa".into(),
            number: "4111 1111 1111 1234".into(),
            exp_month: "12".into(),
            exp_year: "2030".into(),
            code: "123".into(),
        }),
    );
    card.revision_date = 1_700_000_400;

    let mut identity = VaultItem::new(
        "6",
        "Personal Info",
        ItemData::Identity(IdentityData {
            first_name: "Alice".into(),
            last_name: "Example".into(),
            email: "alice@example.com".into(),
            phone: "+81-90-1234-5678".into(),
            address: "Tokyo".into(),
            company: "Example Corp".into(),
        }),
    );
    identity.revision_date = 1_700_000_500;

    let mut ssh_key = VaultItem::new(
        "7",
        "Laptop Key",
        ItemData::SshKey(SshKeyData {
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@laptop".into(),
            private_key: String::new(),
            fingerprint: "SHA256:examplefingerprint".into(),
        }),
    );
    ssh_key.revision_date = 1_700_000_600;

    vault.items = vec![github, vaultwarden, mail, note, card, identity, ssh_key];
    vault
}
