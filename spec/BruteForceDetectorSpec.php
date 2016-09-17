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

    /** @var  int */
    private $maxFailures = 10;

    public function let(\PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->beConstructedWith($this->pdo, $this->maxFailures);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(BruteForceDetector::class);
    }

    public function it_can_detect_a_non_block(\PDOStatement $query)
    {
        $this->pdo->prepare(new Argument\Token\TypeToken('string'))->willReturn($query);

        $query->execute(new Argument\Token\TypeToken('array'))->shouldBeCalled();
        $query->rowCount()->willReturn(1);
        $this->isBlocked(['ip' => '256.256.256.256'])->shouldBe(true);
    }

    public function it_can_detect_a_block(\PDOStatement $query)
    {
        $this->pdo->prepare(new Argument\Token\TypeToken('string'))->willReturn($query);

        $query->execute(new Argument\Token\TypeToken('array'))->shouldBeCalled();
        $query->rowCount()->willReturn(0);
        $this->isBlocked(['ip' => '256.256.256.256'])->shouldBe(false);
    }

    public function it_can_update_watched_values_on_failure(\PDOStatement $query1, \PDOStatement $query2)
    {
        $this->pdo->prepare(new Argument\Token\TypeToken('string'))->willReturn($query1, $query2, false);

        $values = ['ip' => '256.256.256.256', 'user' => 'the.highlander'];
        $query1->execute(['value' => 'ip:' . $values['ip']])->shouldBeCalled();
        $query2->execute(['value' => 'user:' . $values['user']])->shouldBeCalled();

        $this->updateFails($values);
    }

    public function it_can_unblock(\PDOStatement $query)
    {
        $type = 'ip';
        $value = '256.256.256.256';

        $this->pdo->prepare(new Argument\Token\TypeToken('string'))->willReturn($query);
        $query->execute(['value' => $type . ':' . $value])->shouldBeCalled();

        $this->unBlock($type, $value);
    }
}
