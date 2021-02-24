<?php namespace magic3w\phpauth\sdk;

use magic3w\http\url\reflection\URLReflection;

class RefreshToken
{
	
	/**
	 * 
	 * @var SSO
	 */
	private $sso;
	private $token;
	private $expires;
	
	public function __construct($sso, $token, $expires) {
		$this->sso = $sso;
		$this->token = $token;
		$this->expires = $expires;
	}
	
	public function getId() {
		return $this->token;
	}
	
	public function renew() 
	{	
		$request = URLReflection::fromURL(sprintf('%s/token/create.json', $this->sso->getEndpoint()));
		$request->post('type', 'refresh_token');
		$request->post('token', $this->token);
		$request->post('client', $this->sso->getAppId());
		$request->post('secret', $this->sso->getSecret());
		$response = $request->send()->expect(200)->json();
		
		return [
			'access'  => new Token($this, $response->tokens->access->token, $response->tokens->access->expires),
			'refresh' => new RefreshToken($this, $response->tokens->refresh->token, $response->tokens->refresh->expires)
		];
	}
	
}
