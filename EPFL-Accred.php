<?php
/*
 * Plugin Name: EPFL Accred Entra
 * Description: Automatically sync access rights to WordPress from EPFL's institutional data repositories
 * Version:     0.17
 * Author:      Dominique Quatravaux
 * Author URI:  mailto:dominique.quatravaux@epfl.ch
 */

namespace EPFL\Accred;

if ( ! defined( 'ABSPATH' ) ) {
    die( 'Access denied.' );
}

if (! class_exists("EPFL\\SettingsBase") ) {
    require_once(dirname(__FILE__) . "/inc/settings.php");
}
require_once(dirname(__FILE__) . "/inc/cli.php");

function ___($text)
{
    return __($text, "epfl-accred");
}

class Roles
{
    private static function _allroles ()
    {
        return array(
            "administrator" => ___("Administrateurs"),
            "editor"        => ___("Éditeurs"),
            "author"        => ___("Auteurs"),
            "contributor"   => ___("Contributeurs"),
            "subscriber"    => ___("Abonnés")
        );
    }

    static function plural ($role)
    {
        return Roles::_allroles()[$role];
    }

    static function keys ()
    {
        return array_keys(Roles::_allroles());
    }

    static function compare ($role1, $role2)
    {
        if ($role1 === null and $role2 === null) return 0;
        if ($role1 === null) return 1;
        if ($role2 === null) return -1;
        $index1 = array_search($role1, Roles::keys());
        $index2 = array_search($role2, Roles::keys());
        return $index1 <=> $index2;
    }
}

class Controller
{
    const HIDE_ADMINBAR_FOR_ROLES = array('subscriber');

    static $instance = false;
    var $settings = null;
    var $is_debug_enabled = false;

    function debug ($msg)
    {
        if ($this->is_debug_enabled) {
            error_log("Accred: ".$msg);
        }
    }

    public function __construct ()
    {
        $this->settings = new Settings();
    }

    public static function getInstance ()
    {
        if ( !self::$instance ) {
            self::$instance = new self;
        }
        return self::$instance;
    }

    function hook()
    {
        $this->settings->hook();
        (new CLI($this))->hook();
        add_action('openid_save_user', array($this, 'openid_save_user'));
    }

    /**
     * Create or update the Wordpress user from the OpenID data
     */
    function openid_save_user($openid_data)
    {
        $this->debug("-> openid_save_user:\n". var_export($openid_data, true));

        // Getting by slug (this is where we store uniqueid, which never change)
        $user = get_user_by("email", $openid_data["email"]);
        $user_role = $this->settings->get_access_level($openid_data);
        if (! $user_role) {
            $user_role = "";  // So that wp_update_user() removes the right
        }

        if (empty(trim($user_role)) && $user === false) {
            // User unknown and has no role: die() early (don't create it)
            do_action("epfl_accred_403_user_no_role");
            die();
        }

        $userdata = array(
            'user_nicename'  => $openid_data['uniqueid'],  // Their "slug"
            'nickname'       => $openid_data['uniqueid'],
            'user_email'     => $openid_data['email'],
            'user_login'     => $openid_data['gaspar'],
            'first_name'     => $openid_data['given_name'],
            'last_name'      => $openid_data['family_name'],
            'role'           => $user_role,
            'user_pass'      => null);
        $this->debug(var_export($userdata, true));
        if ($user === false) {
            $this->debug("Inserting user");
            $new_user_id = wp_insert_user($userdata);
            if ( ! is_wp_error( $new_user_id ) ) {
                $user = new \WP_User($new_user_id);
            } else {
                echo $new_user_id->get_error_message();
                die();
            }
        } else {  // User is already known to WordPress
            $this->debug("Updating user");

            // if username has changed
            if($openid_data['given_name'] != $user->user_login)
            {
                $this->debug("Username has changed from ".$user->user_login." to ".$openid_data['given_name']);
                // We have to "manually" update username in DB with a request because using 'wp_update_user' won't work...
                global $wpdb;
                $wpdb->update($wpdb->users, array('user_login' => $openid_data['given_name']), array('ID' => $user->ID));
            }

            $userdata['ID'] = $user->ID;
            $user_id = wp_update_user($userdata);
        }

        /* Hide admin bar if necessary */
        update_user_meta( $user->ID, 'show_admin_bar_front', in_array($user_role, $this::HIDE_ADMINBAR_FOR_ROLES)?'false':'true');

        if (empty(trim($user_role))) {
            // User with no role, but exists in database: die late
            // (*after* invalidating their rights in the WP database)
            do_action("epfl_accred_403_user_no_role");
            die();
        }
    }
}

class Settings extends \EPFL\SettingsBase
{
    const SLUG = "epfl_accred";
    /* We don't look in o=epfl,c=ch because some units can be for example in c=ch*/
    const LDAP_BASE_DN = "c=ch";
    const LDAP_HOST = "ldap.epfl.ch";
    var $vpsi_lockdown = false;
    var $is_debug_enabled = false;

    function hook()
    {
        parent::hook();
        $this->add_options_page(
            ___('Réglages de Accred'),                  // $page_title,
            ___('Accred (contrôle d\'accès)'),          // $menu_title,
            'manage_options');                          // $capability
        add_action('admin_init', array($this, 'setup_options_page'));

    }

    /**
    * Validate entered unit label and save unit id in DB if label is correct.
    */
    function validate_unit($unit_label)
    {
        if(empty($unit_label))
        {
            add_settings_error(
			    'unit',
			    'empty',
			    ___('Ne peut pas être vide'),
			    'error'
		    );
        }
        else
        {
            /* Getting LDAP ID from label*/
            $unit_id = $this->get_ldap_unit_id($unit_label);

            if($unit_id === null)
            {
                add_settings_error(
                    'unit',
                    'empty',
                    ___("Unité ".$unit_label." non trouvée dans LDAP"),
                    'error'
                );
            }
            else /* ID has been found, we update it in database */
            {
                $this->update('unit_id', $unit_id);
            }
        }
        return $unit_label;

    }

    /**
     * Prepare the admin menu with settings and their values
     */
    function setup_options_page()
    {
        $this->add_settings_section('section_about', ___('À propos'));
        $this->add_settings_section('section_help', ___('Aide'));
        $this->add_settings_section('section_settings', ___('Paramètres'));

        foreach ($this->role_settings() as $role => $role_setting) {
            $this->register_setting($role_setting, array(
                'type'    => 'string',
                'default' => ''
            ));
        }

        if (! $this->vpsi_lockdown) {
            $this->register_setting('unit', array(
                'type'    => 'string',
                'sanitize_callback' => array($this, 'validate_unit'),
            ));
            // See ->sanitize_unit()
            $this->add_settings_field(
                'section_settings', 'unit', ___('Unité'),
                array(
                    'type'        => 'text',
                    'help' => ___('Si ce champ est rempli, les droits accred de cette unité sont appliqués en sus des groupes ci-dessous.')
                )
            );
        }

        // Not really a "field", but use the rendering callback mechanisms
        // we have:
        $this->add_settings_field(
            'section_settings', 'admin_groups', ___("Contrôle d'accès par groupe"),
            array(
                'help' => ___('Groupes permettant l’accès aux différents niveaux définis par Wordpress.')
            )
        );
    }

    function render_section_about()
    {
        echo "<p>\n";
        echo ___(<<<ABOUT
<a href="https://github.com/epfl-sti/wordpress.plugin.accred">EPFL-Accred</a>
peut être utilisé avec ou sans le <a
href="https://github.com/epfl-sti/epfl-openid-configuration">plug-in
EPFL-OpenID-Configuration</a>. Il crée automatiquement les utilisateurs dans Wordpress,
et synchronise leurs droits depuis les informations institutionnelles
de l'EPFL — Soit depuis Accred, soit depuis un groupe <i>ad
hoc</i>.
ABOUT
);
        echo "</p>\n";
    }

    function render_section_help ()
    {
        echo "<p>\n";
        echo ___(<<<HELP
En cas de problème avec EPFL-Accred veuillez créer une
    <a href="https://github.com/epfl-sti/wordpress.plugin.accred/issues/new"
    target="_blank">issue</a> sur le dépôt
    <a href="https://github.com/epfl-sti/wordpress.plugin.accred/issues">
    GitHub</a>.
HELP
);
        echo "</p>\n";
    }

    function render_section_settings ()
    {
        // Nothing — The fields in this section speak for themselves
    }
    function render_field_admin_groups ()
    {
        $role_column_head  = ___("Rôle");
        $group_column_head = ___("Groupe(s) <small>(si plusieurs, séparés par des virgules)</small>");
        echo <<<TABLE_HEADER
            <table id="admin_groups">
              <tr><th>$role_column_head</th>
                  <th>$group_column_head</th></tr>
TABLE_HEADER;
        foreach ($this->role_settings() as $role => $role_setting) {
            $input_name = $this->option_name($role_setting);
            $input_value = $this->get($role_setting);
            $access_level = Roles::plural($role);
            echo <<<TABLE_BODY
              <tr><th>$access_level</th><td><input type="text" name="$input_name" value="$input_value" class="regular-text"/></td></tr>
TABLE_BODY;
        }
        echo <<<TABLE_FOOTER
            </table>
TABLE_FOOTER;
    }

    /**
     * @return One of the WordPress roles e.g. "administrator", "editor" etc.
     *         or null if the user designated by $openid_data doesn't belong
     *         to any of the roles.
     */
    function get_access_level ($openid_data)
    {
        $this->debug("get_access_level() called for " . var_export($openid_data, true));
        $access_levels = array(
            $this->get_access_level_from_groups($openid_data),
            $this->get_access_level_from_accred($openid_data));
        $this->debug("Before sorting:" . var_export($access_levels, true));
        usort($access_levels, 'EPFL\Accred\Roles::compare');
        $this->debug("After sorting:" . var_export($access_levels, true));
        return $access_levels[0];
    }

    function get_access_level_from_groups ($openid_data)
    {
        $this->debug("EPFL groups: ". var_export($openid_data['groups'], true));
        if (empty($openid_data['groups'])) return null;

        foreach ($this->role_settings() as $role => $role_setting) {
            $this->debug("Checking role: $role ($role_setting)");
            $role_group = $this->get($role_setting);
            $this->debug("Role group found: ".var_export($role_group, true));

            if (empty(trim($role_group))) continue;
            /* If everyone has access for role */
            if($role_group == "*")
            {
                $this->debug("Everyone access granted for role ".$role);
                return $role;
            }

            $user_groups = array_map(function($group) {
                return str_replace("_AppGrpU", "", $group);
            }, $openid_data['groups']);

            $this->debug("Checking group: ".var_export($role_group, true));
            if (in_array($role_group, $user_groups)) {
                $this->debug("Access level from groups is $role");
                return $role;
            }
        }
        return null;
    }

    function get_access_level_from_accred ($openid_data)
    {
        $owner_unit_id = trim($this->get('unit_id'));
        if (empty($owner_unit_id)) {
            return null;
        }

        if (empty($openid_data['authorizations']) or empty(trim($openid_data['authorizations']))) {
            return null;
        }
        $authorizations = explode(",", $openid_data['authorizations']);
        $authorizations = array_filter($authorizations, function ($auth) { 
            return str_contains($auth, "WordPress.Editor:");
        });
        if (empty($authorizations)) {
            return null;
        }

        if ($this->_find_right($owner_unit_id, $authorizations)) {
            $this->debug("Access level from accred is editor");
            return "editor";
        }
        return null;
    }

    function _find_right($owner_unit_id, $authorizations)
    {
        // Check direct authorization
        foreach ($authorizations as $auth) {
            if ($auth == "WordPress.Editor:" . $owner_unit_id) {
                return true;
            }
        }

        // Check if owner_unit_id lies is a parent unit
        foreach ($authorizations as $auth) {
            $auth_unit_id = str_replace("WordPress.Editor:", "", $auth);
            $auth_unit_label = $this->get_ldap_unit_label($auth_unit_id);
            $parents_unit_label = $this->get_ldap_parents_unit_label($auth_unit_label);
            if ($parents_unit_label == null) {
                return null;
            }
            foreach ($parents_unit_label as $parent_unit_label) {
                $parent_unit_id = $this->get_ldap_unit_id($parent_unit_label);
                if ($auth == "WordPress.Editor:" . $parent_unit_id) {
                    return true;
                }
            }
        }
        return false;
    }

    function debug ($msg)
    {
        if ($this->is_debug_enabled) {
            error_log($msg);
        }
    }

    function role_settings ()
    {
        $retval = array();
        if ($this->vpsi_lockdown) {
            $roles = ["subscriber"];
        } else {
            $roles = Roles::keys();
        }
        foreach ($roles as $role) {
            $retval[$role] = $role . "_group";
        }
        return $retval;
    }

    function sanitize_unit ($value)
    {
        return strtoupper(trim($value));
    }

    /**
     * Returns the LDAP unit label from it's id.
     */
    function get_ldap_unit_label($unit_id)
    {
        $dn = self::LDAP_BASE_DN;

        $ds = ldap_connect(self::LDAP_HOST) or die ("Error connecting to LDAP");

        if ($ds === false) {
          error_log("Cannot connect to LDAP");
          return false;
        }

        ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

        $result = ldap_search($ds, $dn, "(&(uniqueidentifier=". $unit_id .")(objectclass=EPFLorganizationalUnit))");

        if ($result === false) {
          error_log(ldap_error($ds));
          return false;
        }

        $infos = ldap_get_entries($ds, $result);

        $unit_label = ($infos['count'] > 0) ? $infos[0]['cn'][0]:null;

        ldap_close($ds);

        return strtoupper($unit_label);
    }

    /**
     * Returns the LDAP unit id from it's label.
     */
    function get_ldap_unit_id($unit_label)
    {
        $dn = self::LDAP_BASE_DN;

        $ds = ldap_connect(self::LDAP_HOST) or die ("Error connecting to LDAP");

        if ($ds === false) {
          error_log("Cannot connect to LDAP");
          return false;
        }

        ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

        $result = ldap_search($ds, $dn, "(&(cn=". $unit_label .")(objectclass=EPFLorganizationalUnit))");

        if ($result === false) {
          error_log(ldap_error($ds));
          return false;
        }

        $infos = ldap_get_entries($ds, $result);

        $unit_id = ($infos['count'] > 0) ? $infos[0]['uniqueidentifier'][0]:null;

        ldap_close($ds);

        return $unit_id;
    }

    /**
     * Returns the parent LDAP unit label from an unit label.
     */
    function get_ldap_parents_unit_label($unit_label)
    {
        $dn = self::LDAP_BASE_DN;

        $ds = ldap_connect(self::LDAP_HOST) or die ("Error connecting to LDAP");

        if ($ds === false) {
          error_log("Cannot connect to LDAP");
          return false;
        }

        ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

        $result = ldap_search($ds, $dn, "(&(ou=$unit_label)(objectClass=organizationalUnit))");

        if ($result === false) {
          error_log(ldap_error($ds));
          return false;
        }

        $infos = ldap_get_entries($ds, $result);
        $dn = explode(",", $infos[0]['dn']);
        $ou = array_filter($dn, function ($val) { 
            return str_contains($val, "ou=");
        });
        $parents_unit_label = array_map(function($val) {
            return strtoupper(str_replace("ou=", "", $val));
        }, $ou);

        ldap_close($ds);

        return $parents_unit_label;
    }
}


if (file_exists(dirname(__FILE__) . "/site.php")) {
    require_once(dirname(__FILE__) . "/site.php");
}

Controller::getInstance()->hook();
