<?php

namespace Raajen\OAuth2\Client\Test\Provider;

use League\OAuth2\Client\Tool\QueryBuilderTrait;
use PHPUnit\Framework\TestCase;
use Mockery;

use Raajen\OAuth2\Client\Provider\Dropbox;

class DropboxTest extends TestCase
{
	use QueryBuilderTrait;

	/**
	 * @var Dropbox
	 */
	protected $provider;

	protected function setUp(): void
	{
		$this->provider = new Dropbox([
			'clientId' => 'mocked_client_id',
			'clientSecret' => 'mocked_client_secret',
			'redirectUri' => 'https://example.com'
		]);
	}

	public function tearDown(): void
	{
		Mockery::close();
		parent::tearDown();
	}

	public function testState()
	{
		$this->provider->setState('some_custom_state_data');
		$state = $this->provider->getState();
		$this->assertEquals('some_custom_state_data', $state);
	}

	public function testArgsSetter()
	{
		$this->provider->set('token_access_type', 'offline');
		$this->provider->set('approval_prompt', []);

		$args = $this->provider->getArgs();

		$this->assertArrayHasKey('token_access_type', $args);
		$this->assertArrayHasKey('approval_prompt', $args );

		$this->assertEquals('offline', $args['token_access_type']);
		$this->assertIsArray($args['approval_prompt']);
	}

	public function testStateFailed()
	{
		$this->provider->setState('some_custom_state_data');
		$state = $this->provider->getState();
		$this->assertNotEquals('some_random_custom_state_data', $state );
	}

	public function testAuthorizationUrl()
	{
		$this->provider->setState('some_custom_state_data');
		$this->provider->set('approval_prompt', []);
		$this->provider->set('token_access_type', 'offline');

		/**
		 * @var string
		 */
		$auth_url = $this->provider->getAuthorizationUrl();
		$parsed_url = parse_url($auth_url);
		parse_str($parsed_url['query'], $query);

		$this->assertArrayHasKey('client_id', $query);
		$this->assertArrayHasKey('redirect_uri', $query);
		$this->assertArrayHasKey('state', $query);
		$this->assertArrayHasKey('scope', $query);
		$this->assertArrayHasKey('response_type', $query);
		$this->assertArrayHasKey('token_access_type', $query);
		$this->assertArrayNotHasKey('approval_prompt', $query);
		$this->assertNotNull($this->provider->getState());
	}

	public function testAuthUrlThrowsException()
	{
		$this->expectException('\\Raajen\\OAuth2\\Client\\Exception\\NoStateException');
		$this->provider->getAuthorizationUrl();
	}

	public function testScopes()
	{
		$options = ['scope' => [uniqid(), uniqid()]];
		$this->provider->setState('some_custom_state');

		/**
		 * @var string
		 */
		$auth_url = $this->provider->getAuthorizationUrl($options);
		$parsed_url = parse_url($auth_url);
		parse_str($parsed_url['query'], $url);

        $this->assertArrayHasKey('scope', $url);
		$this->assertEquals(implode(',', $options['scope']), $url['scope']);
	}

	public function testBaseAuthorizationUrl()
	{
		$url = $this->provider->getBaseAuthorizationUrl();
		$uri = parse_url($url);

		$this->assertEquals('/oauth2/authorize', $uri['path']);
	}

	public function testBaseTokenUrl()
	{
		$url = $this->provider->getBaseAccessTokenUrl();
		$uri = parse_url($url);

		$this->assertEquals('/oauth2/token', $uri['path']);
	}

	public function testResourceOwnerDetailsUrl()
	{

		$url = $this->provider->getResourceOwnerDetailsUrl();
		$uri = parse_url($url);

		$this->assertEquals('/2/users/get_current_account', $uri['path']);
	}

	public function testGetAccessToken()
    {
		/**
		 * @var object
		 */
        $response = Mockery::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn('{"access_token": "mock_access_token", "token_type": "bearer", "account_id": "12345"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

		/**
		 * @var object
		 */
        $client = Mockery::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);

		/**
		 * @var object
		 */
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('mock_access_token', $token->getToken());
        $this->assertNull($token->getExpires());
        $this->assertNull($token->getRefreshToken());
        $this->assertEquals('12345', $token->getResourceOwnerId());
    }

	public function testUserData()
	{
		$name = uniqid();
		$userId = rand(1000, 9999);

		/**
		 * @var object
		 */
		$postResponse = Mockery::mock('Psr\Http\Message\ResponseInterface');
		$postResponse->shouldReceive('getBody')->andReturn('{"access_token": "mock_access_token", "token_type": "bearer", "account_id": "12345"}');
		$postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

		/**
		 * @var object
		 */
		$userResponse = Mockery::mock('Psr\Http\Message\ResponseInterface');
		$userResponse->shouldReceive('getBody')->andReturn('{"account_id": "'.$userId.'", "name": {"display_name": "'.$name.'", "familiar_name": "John", "given_name": "John", "surname": "Doe"}, "referral_link": "https://www.dropbox.com/referrals/a1b2c3d4e5f6h7", "country": "US", "locale": "en", "is_paired": false, "team": {"name": "Acme Inc.", "team_id": "dbtid:1234abcd"}, "quota_info": {"shared": 253738410565, "quota": 107374182400000, "normal": 680031877871}}');
		$userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

		/**
		 * @var object
		 */
		$client = Mockery::mock('GuzzleHttp\ClientInterface');
		$client->shouldReceive('send')
			->times(2)
			->andReturn($postResponse, $userResponse);

		$this->provider->setHttpClient($client);

		$token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

		/**
		 * @var object
		 */
		$user = $this->provider->getResourceOwner($token);

		$this->assertEquals($userId, $user->getId());
		$this->assertEquals($userId, $user->toArray()['account_id']);
		$this->assertEquals($name, $user->getName());
		$this->assertEquals($name, $user->toArray()['name']['display_name']);
	}

}