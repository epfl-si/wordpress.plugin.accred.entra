# EPFL Accred Entra

Automatically synchronises WordPress user accounts and roles from
EPFL's institutional identity provider using OpenID Connect (Entra ID).

## Requirements

- WordPress 5.x or later
- [OpenID Connect Generic][oidc-plugin] plugin
- PHP with LDAP extension enabled
- Network access to `ldap.epfl.ch` and `api.epfl.ch`

[oidc-plugin]: https://wordpress.org/plugins/daggerhart-openid-connect-generic

## Installation

1. Upload the plugin folder to `/wp-content/plugins/`.
2. Activate the plugin in the **Plugins** admin screen.
3. Go to **Settings > Accred** to configure the plugin.

## Configuration

| Setting | Description |
| ------- | ----------- |
| Unit    | EPFL organisational unit short name (e.g. `si`) |
| Groups  | Entra group name per WordPress role |

Each role (`administrator`, `editor`, `author`, `contributor`,
`subscriber`) can be mapped to one or more Entra groups, separated
by commas. Use `*` to grant that role to every authenticated user.

## How it works

On each login, the plugin reads the OIDC token claims and either
creates or updates the WordPress user account. The assigned role is
the highest one matched by either:

- **Group membership** — the user's `groups` claim is matched
  (case-insensitively, stripping the `_AppGrpU` suffix) against
  the groups configured in the settings.
- **Accred rights** — the `rights` claim is checked for a
  `WordPress.Editor:<unit_id>` entry matching the configured unit.

If neither source yields a role, the user is denied access and the
`epfl_accred_403_user_no_role` action is fired.

If the `rights` claim is absent from the token, the plugin fetches
it from `https://api.epfl.ch/v2/oidc/userinfo`.

Username and e-mail collisions are resolved automatically on account
creation by appending a suffix to the existing conflicting account.
