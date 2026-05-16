# nostr-oicd

NOTE: This project is still in developement. Use carefully.

This is a service that provides OIDC functionality for [NOSTR](https://github.com/nostr-protocol/nips/blob/master/01.md). Originally thought for (Cashu Mints)[https://github.com/cashubtc/nuts/blob/main/21.md] clear auth.

The two main authentification functionalities available are:
- Authorication code with PKCE. 
- Device Authentification.

This service is thought to be a simpler replacement of [Keycloak](https://github.com/keycloak/keycloak) with NOSTR first
party functionality.

This service allows for open signup using Nostr WoT. The Vertex relay is used to avoid letting Bots or fake accounts in. 

All secrets are stored securely in a keychain. The database only store fingerprints of the secrets so they can be
queried later.

## How to run

### Docker Compose (Recommended)

1. Copy `.env.example` to `.env`, and adjust environment variables based on your needs.

2. Run:
   ```bash
   docker compose up -d
   ```

3. Access the dashboard at `http://localhost:8082/admin/login`

### Local Development

1. Copy `.env.example` to `.env`, and adjust environment variables based on your needs.

2. Build and run:
   ```bash
   ./build-local.sh
   ./run-local.sh
   ```

3. Access the dashboard at `http://localhost:8082/admin/login`

## Todos

- Client secret rotation and showing of secret.
- Add Google sign on.

### Support 

Pull requests and suggestions are always welcomed. The more people have eyes on this the better.

If you can donate monetarily it would be greatly appreciated. The funds would go to the development of the mint and
servers for testing.

You can contact me on nostr:

*on-chain silent payments*
```
sp1qq0fju879lh2rgvwjjd7e78pg4gnr7a8aumth8qlezdgjs2rwzk7ssqhrm5g4pmvuv244zu5h87d55uyys804ldutjkav6kwupwh2nke9yys3v2j2
```

*Donate with lightning*
```
npub1m03lx54jdf4c5pnghcjeqracehcp7h58zsgd9rtezk946yuzwfyqh9gx6a@npub.cash
```


*Donate with on-chain*

```
bc1p7penxt9gw7gg5a50dq6h47hdkj5yy8cpp0wwvgl2slutjg5u2frsqf4grz
```
