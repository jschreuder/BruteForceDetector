<?php

namespace spec\Spot\BruteForceDetector;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Spot\BruteForceDetector\BruteForceDetector;

/** @mixin  BruteForceDetector */
class BruteForceDetectorSpec extends ObjectBehavior
{
    /** @var  \PDO */
    private $pdo;

    public function let(\PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->beConstructedWith($pdo);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(BruteForceDetector::class);
    }
}
