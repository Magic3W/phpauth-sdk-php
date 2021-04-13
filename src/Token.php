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
	 * 
	 * @deprecated since v0.1.1 (20210331)
	 * @return mixed
	 */
	public function getTokenInfo() {
		static $cache = null;
		
		if ($cache !== null) { return $cache; }
		
		$request  = new Request($this->sso->getEndpoint() . '/auth/index/' . $this->token . '.json');
		$response = $request->send()->expect(200)->json();
		
		return $cache = $response;
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
