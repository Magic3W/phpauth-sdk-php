<?php namespace magic3w\phpauth\sdk;

use CURLFile;
use Exception;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
Use spitfire\io\request\Request;
use magic3w\http\url\reflection\URLReflection;

class SSO
{
	
	/**
	 * 
	 * @var string
	 */
	private $endpoint;
	
	/**
	 * 
	 * @var int
	 */
	private $appId;
	
	/**
	 * 
	 * @var string
	 */
	private $appSecret;
	
	/**
	 * 
	 * @var Configuration
	 */
	private $jwt;
	
	/**
	 * 
	 * @param string $credentials
	 */
	public function __construct(string $credentials) 
	{
		$reflection = URLReflection::fromURL($credentials);
		
		$this->endpoint  = rtrim($reflection->getProtocol() . '://' . $reflection->getHostname() . ':' . $reflection->getPort() . $reflection->getPath(), '/');
		$this->appId     = (int)$reflection->getUser();
		$this->appSecret = $reflection->getPassword();
		
		if (!$this->appSecret) {
			throw new Exception('App Secret is missing', 1807021658);
		}
		
		$this->jwt = Configuration::forSymmetricSigner(new Sha256, InMemory::base64Encoded($this->appSecret));
	}

	/**
	 * Generates a URL to direct the user agent to in order to initiate
	 * the authentication. Please note that the oAuth 2.0 protocol uses the user
	 * agent for this 'request', therefore the server itself is not performing 
	 * the request at all.
	 * 
	 * I would like to avoid using the word request for whatever is happening
	 * at this stage of the connection.
	 * 
	 * @param string $state
	 * @param string $verifier_challenge
	 * @param string $returnto
	 * @param int|null $audience The app ID of the application this client wishes to access data from. This may
	 *        be null if the application wishes to access the client account on PHPAS.
	 * @return string
	 */
	public function makeAccessCodeRedirect(string $state, string $verifier_challenge, string $returnto, int $audience = null) : string
	{
		
		$request = new Request(sprintf('%s/auth/oauth', $this->endpoint));
		$request->get('response_type', 'code');
		$request->get('client', $this->appId);
		$request->get('state', $state);
		
		if ($audience) { 
			$request->post('audience', (string)$audience); 
		}
		
		$request->get('redirect', $returnto);
		$request->get('code_challenge', hash('sha256', $verifier_challenge));
		$request->get('code_challenge_method', 'S256');

		return strval($request);
	}
	
	/**
	 * Tokens can be retrieved using three different mechanisms.
	 * 
	 * 1. Provide an access code that a user generated. This is used during the oAuth flow
	 * 2. Provide application specific credentials, yields a client token
	 * 3. Provide a refresh token.
	 * 
	 * This mechanism intends to make it simple for the applications to generate new tokens
	 * for the first scenario, by providing a code and a verifier to the table.
	 * 
	 * @param string $code
	 * @param string $verifier
	 * @param int|null $audience
	 * @return array{'access': Token, 'refresh': RefreshToken}
	 */
	public function token(string $code, string $verifier, int $audience = null) : array
	{
		$request = new Request(sprintf('%s/token/create.json', $this->endpoint));
		$request->post('code', $code);
		$request->post('type', 'code');
		$request->post('client', (string)$this->getAppId());
		$request->post('secret', $this->appSecret);
		$request->post('verifier', $verifier);
		
		if ($audience) { 
			$request->post('audience', (string)$audience); 
		}
		
		$response = $request->send()->expect(200)->json();
		
		return [
			'access'  => new Token($this, $this->jwt->parser()->parse($response->tokens->access->token), $response->tokens->access->expires),
			'refresh' => new RefreshToken($this, $response->tokens->refresh->token, $response->tokens->refresh->expires)
		];
	}
	
	/**
	 * Refreshes an access and refresh token by passing a refresh token to the 
	 * system as grant.
	 * 
	 * The token must be a string, if you held onto the `Token` object you received
	 * from the API, you can extract the code by calling getToken.
	 * 
	 * @param string $token
	 * @return array{'access': Token, 'refresh': RefreshToken}
	 */
	public function refresh(string $token) : array
	{
		$token = new RefreshToken($this, $token, null);
		return $token->renew();
	}
	
	/**
	 * Returns an access token that allows the application to access it's own credentials
	 * on the server.
	 * 
	 * @param int|null $audience
	 * @return Token
	 */
	public function credentials(int $audience = null) 
	{
		$request = new Request(URLReflection::fromURL(sprintf('%s/token/create.json', $this->endpoint)));
		$request->post('type', 'client_credentials');
		$request->post('client', (string)$this->getAppId());
		$request->post('secret', $this->appSecret);
		
		/**
		 * If the application did ask for credentials to another application, we will add this
		 * to the audience.
		 */
		if ($audience) { 
			$request->post('audience', (string)$audience); 
		}
		
		$response = $request->send()->expect(200)->json();
		
		return new Token($this, $response->tokens->access->token, $response->tokens->access->expires);
	}
	
	/**
	 * The base URL of the PHPAuth Server
	 * 
	 * @return string
	 */
	public function getEndpoint() : string
	{
		return $this->endpoint;
	}
	
	/**
	 * The app id of the application that is authenticating this client.
	 * 
	 * @return int
	 */
	public function getAppId() : int
	{
		return $this->appId;
	}
	
	/**
	 * Returns the secret the system is using to communicate with the server. This can be
	 * used by refresh tokens to renew their lease.
	 * 
	 * @return string
	 */
	public function getSecret() {
		return $this->appSecret;
	}
	
	/**
	 * 
	 * @deprecated since version 0.1-dev
	 * @return object
	 */
	public function getAppDrawer() {
		$url = $this->endpoint . '/appdrawer/index.json';
		$request  = new Request($url);
		
		$response = $request->send()->expect(200)->json();
		
		return $response;
	}
	
	/**
	 * 
	 * @deprecated since version 0.1-dev
	 * @return string
	 */
	public function getAppDrawerJS() {
		return $this->endpoint . '/appdrawer/index.js';
	}
	
	/**
	 * 
	 * @return object
	 */
	public function getGroupList() : object
	{
		$url  = new Request($this->endpoint . '/group/index.json');
		$resp = $url->send()->expect(200)->json();
		
		return $resp->payload;
	}
	
	/**
	 * 
	 * @param string $id
	 * @return object
	 */
	public function getGroup(string $id) : object
	{
		$url  = new Request($this->endpoint . '/group/detail/' . $id . '.json');
		return $url->send()->expect(200)->json()->payload;
	}
	
	
	/**
	 * This method allows your client to push a custom scope onto the server. This scope
	 * can then be used by third party applications to request access to parts of the user's
	 * data that you requested be fenced off.
	 * 
	 * @param string $id
	 * @param string $name
	 * @param string $description
	 * @param string $icon
	 * @return void
	 */
	public function putScope($id, $name, $description, $icon = null) : void
	{
		$request = new Request(sprintf('%s/scope/create/%s.json', $this->getEndpoint(), $id));
		
		$request->get('token', (string)$this->credentials()->getId());
		$request->post('name', $name);
		$request->post('description', $description);
		$request->post('icon', new CURLFile($icon));
		$request->send();
	}
	
	/**
	 * Generate a logout link. The logout flow is best described as follows:
	 * 
	 * 1. Client generates a logout link, which contains a return URL to direct the user to on successful logout
	 * 2. Resource owner is directed to the logout location
	 * 3. Authentication server terminates the session, and all authenticated tokens that depend on it
	 * 4. Authentication directs the resource owner to the return URL
	 * 5. Client destroys the session on their end.
	 * 
	 * Alternatively, the client can execute the 5fth point first.
	 * 
	 * Asynchronously, the Authentication server will start notifying all applications
	 * using tokens in the current session to destroy them. 
	 * 
	 * Invoking this endpoint is optional, it only ends the session on the authentication
	 * server, allowing your application to display a "log out" from all 
	 * 
	 * @param Token $token
	 * @param string $returnto
	 * @return string
	 */
	public function getLogoutLink(Token $token, string $returnto) : string
	{
		return $this->endpoint . '/user/logout?' . http_build_query(['returnto' => $returnto, 'token' => $token->getId()]);
	}
	
}

