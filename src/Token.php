<?php namespace magic3w\phpauth\sdk;

use Exception;
use spitfire\io\request\Request;

class Token
{
	
	/**
	 * 
	 * @var SSO
	 */
	private $sso;
	
	/**
	 * 
	 * @var string
	 */
	private $token;
	
	/**
	 * 
	 * @var int
	 */
	private $expires;
	
	/**
	 * 
	 * @param SSO $sso
	 * @param string $token
	 * @param int $expires
	 */
	public function __construct(SSO $sso, string $token, int $expires)
	{
		$this->sso = $sso;
		$this->token = $token;
		$this->expires = $expires;
	}
	
	/**
	 * Returns the token's ID
	 * 
	 * @return string
	 */
	public function getId() {
		return $this->token;
	}
	
	/**
	 * Indicates whether the session was expired, or whether the session is still active.
	 * 
	 * @return bool
	 */
	public function isExpired() : bool
	{
		return time() > $this->expires;
	}
	
	public function isAuthenticated() {
		return $this->expires > time();
	}
}
