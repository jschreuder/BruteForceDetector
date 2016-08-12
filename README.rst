BruteForceDetector
==================

.. image:: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/badges/build.png?b=master
   :target: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/?branch=master
   :alt: Build status
.. image:: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/badges/quality-score.png?b=master
   :target: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/?branch=master
   :alt: Scrutinizer Code Quality
.. image:: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/badges/coverage.png?b=master
   :target: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/?branch=master
   :alt: Code Coverage

This library keeps a log in your database that keeps track of login failures
for example. This should allow you to prevent someone from brute forcing a
password for example, and also provide some additional protection against
timing attacks.

The library is very basic and makes no assumptions on how you process a block.
It comes with some defaults that should probably do in many project, but all
use cases are different.

Main Interface methods
----------------------

The base of this library consists of two methods: one to check if a request
needs to be blocked, and a second to add a failure to the log. To log & execute
the checks these must be passed in as an array of types & values. For example
the following:

.. code:: php

  $checks = [
      'ip' => '127.0.0.1',
      'username' => 'admin',
  ];

This will check for both of these values if the limit of failures set upon them
has been passed. In the database this will actually check the values
``"ip:127.0.0.1"`` and ``"username:admin"``. The index of the array is
considered the type and may not contain a colon.

The library comes with a few preset constants: ``BruteForceDetector::TYPE_IP``
for IP addresses, ``BruteForceDetector::TYPE_USER`` for usernames and
``BruteForceDetector::TYPE_TOKEN`` for session tokens.

``isBlocked(array $checks)``

This will answer either true or false on whether the limit of failures has been
passed. The limit is set during construction of the ``BruteForceDetector``
instance and defaults to 10000.

``updateFails(array $checks)``

Adds one failure to the log of each of the given type/value pairs.

Managing blocks
---------------

The library itself does not automatically expire failure logs or unblock. So
you probably need to implement this yourself. The library does provide two
methods to assist with this:

``expireLowFailures($maxAge = 3600, $maxFailPercentage = 0.5)``

This method will check all logs updated before the timespan given in
``$maxAge`` and delete them if their number of failures is below the given
``$maxFailPercentage`` of the number of failures that will cause the value to
be blocked. The defaults are to check for updates within the last hour (3600
seconds) and with failure rate of 50 or lower (0.5% of 10000).

It is recommended to put this in a CRON-job to run hourly. You could also have
a second one running daily with a higher ``$maxAge`` and
``$maxFailPercentage``.

``unBlock($type, $value)``

Once a value is blocked it will not unblock automatically. You can use this
method to unblock a given value and type by removing their log.

``getBlockedValues($maxAge = 2419200)``

Will return a list of all type/value combinations blocked within the given
period. This defaults to the last 4 weeks.

Usage example
-------------

Let's say for example you have the following code:

.. code:: php

  use Psr\Http\Message\ServerRequestInterface;
  class LoginController {
      private $authService;

      public function __construct(AuthService $authService)
      {
          $this->authService = $authService;
      }

      function login(ServerRequestInterface $request)
      {
          $requestParams = $request->getParsedBody();
          if (!$this->authService->login($requestParams['user'], $requestParams['pass'])) {
              return 'FAIL';
          }
          return 'SUCCESS';
      }
  }

This may be brute forced without impunity, so let's implement the BruteForceDetector:

.. code:: php

  use Psr\Http\Message\ServerRequestInterface;
  class LoginController {
      private $authService;
      private $bruteForceDetector;

      public function __construct(AuthService $authService, BruteForceDetector $bruteForceDetector)
      {
          $this->authService = $authService;
          $this->bruteForceDetector = $bruteForceDetector;
      }

      function login(ServerRequestInterface $request)
      {
          $requestParams = $request->getParsedBody();
          $checks = [
              BruteForceDetector::TYPE_IP => $request->getClientIp(),
              BruteForceDetector::TYPE_USER => $requestParams['user'],
          ];

          // Block if already too many tries for either the given user or from current IP
          if ($this->bruteForceDetector->isBlocked($checks)) {
              return 'BLOCKED';
          }

          if (!$this->authService->login($requestParams['user'], $requestParams['pass'])) {
              $this->bruteForceDetector->updateFails($checks);
              return 'FAIL';
          }

          return 'SUCCESS';
      }
  }

TODO
----

- Improve README/documentation
- Get this thing fully tested
- Add a ``BanningService`` which uses or extends this class to set temporary
  and permanent bans. Probably by preempting the ``isBlocked()`` check by an
  ``isBanned()`` check using the ``isBlocked()`` to instigate the bans.
