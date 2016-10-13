<?php
namespace Drupal\auth0\Event;

use Symfony\Component\EventDispatcher\Event;

class Auth0UserSignupEvent extends Event {
  public $event_name = 'auth0.signup';
  protected $user;
  protected $auth0Profile;

  public function __construct($user, $auth0Profile) {
    $this->user = $user;
  }

  public function getUser() {
    return $this->user;
  }

  public function getAuth0Profile() {
    return $this->auth0Profile;
  }
}