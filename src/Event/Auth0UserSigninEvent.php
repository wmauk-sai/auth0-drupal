<?php
namespace Drupal\auth0\Event;

use Symfony\Component\EventDispatcher\Event;

/**
 * User signin event.
 */
class Auth0UserSigninEvent extends Event {

  const NAME = 'auth0.signin';

  /**
   * @var \Drupal\user\UserInterface
   */
  protected $user;

  /**
   * @var array
   */
  protected $auth0Profile;
  
  /**
   * @var string
   */
  protected $refreshToken;
  
  /**
   * @var timestamp
   */
  protected $expiresAt;
  
  /**
   * Initialize the event.
   * @param \Drupal\user\UserInterface $user
   * @param array $auth0Profile
   * @param string $refreshToken the refresh token
   * @param timestamp $expiresAt the time when the idToken expires in unix timestamp (seconds only)
   */
  public function __construct($user, $auth0Profile, $refreshToken, $expiresAt) {
    $this->user = $user;
    $this->auth0Profile = $auth0Profile;
    $this->refreshToken = $refreshToken;
    $this->expiresAt = $expiresAt;
  }

  /**
   * Get the drupal user.
   * @return \Drupal\user\UserInterface
   */
  public function getUser() {
    return $this->user;
  }

  /**
   * Get the Auth0 profile.
   * @return array
   */
  public function getAuth0Profile() {
    return $this->auth0Profile;
  }

  /**
   * Get the refresh token.
   * @return string token
   */
  public function getRefreshToken() {
    return $this->refreshToken;
  }

  /**
   * Get the time when the ID token expires.
   * @return unix time when token expires
   */
  public function getExpiresAt() {
    return $this->expiresAt;
  }


}
