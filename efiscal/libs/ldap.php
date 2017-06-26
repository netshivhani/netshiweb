<?php

$config = $_SERVER['DOCUMENT_ROOT'].'/efiscal/config.php';
require_once ( $config );

// LDAP Login
function Login ($cn,$ldappass) {
	$current_error_reporting = error_reporting();
	error_reporting(E_ERROR);
	global $ldap_host, $base_dn, $ad_domain, $grouparray;
	$result = (object) array('auth' => false, 'ldaperror' => '', 'displayname' => '', 'email' => '', 'CBS' => false);

	// connect to ldap server
	$ldapconn = @ldap_connect($ldap_host) or die("Could not connect to LDAP server.");
	ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
	ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);

	$ldappass = stripslashes(html_entity_decode($ldappass));

	if ($ldapconn) {
		// binding to ldap server
		$ldapbind = ldap_bind($ldapconn, $cn.'@'.$ad_domain, $ldappass);

		// verify binding
		if ($ldapbind) {
			$filter="(sAMAccountName=$cn)";
			$justthese = array("samaccountname","displayname","memberof","mail");
			$sr=ldap_search($ldapconn,$base_dn,$filter,$justthese);
			$userinfo = ldap_get_entries($ldapconn,$sr);
			if ($userinfo["count"] > 0)
			{
				$result->auth = true;
				if ($userinfo[0]["displayname"][0] !== null) $result->displayname = $userinfo[0]["displayname"][0];
				if ($userinfo[0]["mail"][0] !== null) $result->email = $userinfo[0]["mail"][0];
				if ($userinfo[0]["memberof"] !== null)
				{
					for($i=0; $i<$userinfo[0]["memberof"]["count"]; $i++)
					{
						$CBS = false;
						$group = $userinfo[0]["memberof"][$i];
						// $grouparray comes from config.php
						if(in_array($group,$grouparray) && !$CBS)
						{
							$CBS = true;
							$result->CBS = true;
						}
					}
				}
			} else {
				$result->ldaperror = "Unable locate user ".$cn." in ".$ad_domain;
			}
		} else {
			$result->ldaperror = ldap_error($ldapconn);
		}
		ldap_unbind($ldapconn);
	}
	error_reporting($current_error_reporting);
	return $result;
}

// LDAP search
function LdapSearch ($cn) {
	$current_error_reporting = error_reporting();
	error_reporting(E_ERROR);
	global $ldap_anon_host, $base_anon_dn;
	$result = (object) array('count' => 0, 'ldaperror' => '', 'entries' => array());

	// connect to ldap server
	$ldapconn = @ldap_connect($ldap_anon_host) or die("Could not connect to LDAP server.");

	if ($ldapconn) {
		// binding to ldap server
		$ldapbind = ldap_bind($ldapconn);

		// verify binding
		if ($ldapbind) {
			$filter="(cn=$cn*)";
			$justthese = array("cn","givenname","preferredname","sn","mail");
			$sr=ldap_search($ldapconn,$base_anon_dn,$filter,$justthese);
			$userinfo = ldap_get_entries($ldapconn,$sr);
			if ($userinfo["count"] > 0)
			{
				$result->count = $userinfo["count"];
				
				foreach ($userinfo as $userresult) {				
					$displayname = "";
					$usermail = "";
					$usercn = $userresult["cn"][0];
					
					if ($userresult["preferredname"][0] !== null) {
						$displayname = $userresult["preferredname"][0]." ".$userresult["sn"][0];
					} else {
						$displayname = $userresult["givenname"][0]." ".$userresult["sn"][0];
					}
					
					if ($userresult["mail"][0] !== null) {
						$usermail = $userresult["mail"][0];
					}
			
					$result->entries[] = array("cn" => $usercn, "displayname" => $displayname, "mail" => $usermail);
				}

			} else {
				$result->ldaperror = "Unable locate user ".$cn." in ".$ad_domain;
			}
		} else {
			$result->ldaperror = ldap_error($ldapconn);
		}
		ldap_unbind($ldapconn);
	}
	error_reporting($current_error_reporting);
	return $result;
}

?>
