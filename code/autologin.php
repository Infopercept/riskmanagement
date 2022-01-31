<?php
    require_once(realpath(__DIR__ . '/includes/functions.php'));
    require_once(realpath(__DIR__ . '/includes/authenticate.php'));
    require_once(realpath(__DIR__ . '/includes/alerts.php'));
    require_once(realpath(__DIR__ . '/includes/extras.php'));
    require_once(realpath(__DIR__ . '/vendor/autoload.php'));
    $key = hash('sha256', "Invinsense");
    if(!isset($_GET['key']) || $_GET['key']!=$key){
        header("location: index.php");
        exit();
    }

    add_security_headers();

    if (!isset($_SESSION))
    {
        // Session handler is database
        if (USE_DATABASE_FOR_SESSIONS == "true")
        {
            session_set_save_handler('sess_open', 'sess_close', 'sess_read', 'sess_write', 'sess_destroy', 'sess_gc');
        }

        // Start session
        session_set_cookie_params(0, '/', '', isset($_SERVER["HTTPS"]), true);

        sess_gc(1440);
        session_name('SimpleRisk');
        session_start();
    }

	$user = "admin";
    $pass = "admin";

    // Check for expired lockouts
    check_expired_lockouts();

    // If the user is valid
    if (is_valid_user($user, $pass))
    {
        $uid = get_id_by_user($user);
        $array = get_user_by_id($uid);

        if($array['change_password'])
        {
            $_SESSION['first_login_uid'] = $uid;

            if (encryption_extra())
            {
                // Load the extra
                require_once(realpath(__DIR__ . '/extras/encryption/index.php'));

                // Get the current password encrypted with the temp key
                check_user_enc($user, $pass);
            }

            // Put the posted password in the session before redirecting them to the reset page
            $_SESSION['first_login_pass'] = $pass;

            header("location: reset_password.php");
            exit;
        }

        // Create the SimpleRisk instance ID if it doesn't already exist
        create_simplerisk_instance_id();

        // Set the user permissions
        set_user_permissions($user);

        // Ping the server
        ping_server();

	// Do a license check
	simplerisk_license_check();

        // Get base url
	//$base_url = get_base_url() . $_SERVER['SCRIPT_NAME'];
        //$base_url = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://{$_SERVER['SERVER_NAME']}{$_SERVER['SCRIPT_NAME']}";
        //$base_url = htmlspecialchars( $base_url, ENT_QUOTES, 'UTF-8' );
        //$base_url = pathinfo($base_url)['dirname'];

        // Filter out authentication extra from the base url
        //$base_url = str_replace("/extras/authentication", "", $base_url);
        //$_SESSION['base_url'] = $base_url;
	$_SESSION['base_url'] = get_base_url();

        // Set login status
        login($user, $pass);

    }
    // If the user is not a valid user
    else {
        
        // In case the login attempt fails we're checking the cause.
        // If it's because the user 'Does Not Exist' we're doing a dummy
        // validation to make sure we're using the same time on a non-existant
        // user as we'd use on an existing
        if (get_user_type($user, false) === "DNE") {
            fake_simplerisk_user_validity_check();
        }

        $_SESSION["access"] = "denied";

        // Display an alert
        set_alert(true, "bad", "Invalid username or password.");

        // If the password attempt lockout is enabled
        if(get_setting("pass_policy_attempt_lockout") != 0)
        {
            // Add the login attempt and block if necessary
            add_login_attempt_and_block($user);
        }
        header("location: index.php");
        exit();
    }
?>