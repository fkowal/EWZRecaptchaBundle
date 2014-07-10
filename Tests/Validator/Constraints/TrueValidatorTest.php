<?php
namespace EWZ\Bundle\RecaptchaBundle\Validator\Constraints;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\HttpFoundation\Request;

/**
 * @coversDefaultClass EWZ\Bundle\RecaptchaBundle\Validator\Constraints\TrueValidator
 * @covers ::__construct
 */
class TrueValidatorTest extends \PHPUnit_Framework_TestCase {

    /**
     * @test
     * @covers ::<public>
     * @covers ::<protected>
     */
    public function afterSuccessfulResponseNoViolationShouldHappen()
    {
        // arrange
        $container = $this->getContainer();

        $httpRequest = $this->getRequestMock($this->returnValue($this->getHttpResponse("true\nsuccess")));

        $httpClient = $this->getHttpClientMock(
            $this->returnValue($httpRequest)
        );

        $validator = new TrueValidator($container);
        $validator->setClient($httpClient);

        $constraint =  new True();
        $context = $this->getMockBuilder('Symfony\Component\Validator\ExecutionContextInterface')->getMock();
        // assert
        $context->expects($this->never())
            ->method('addViolation');

        // act
        $validator->initialize($context);
        $validator->validate('x', $constraint);
    }

    /**
     * @test
     */
    public function afterTimeoutCaptchaIsValid()
    {
        // arrange
        $container = $this->getContainer();

        $exception = new \Guzzle\Http\Exception\CurlException();
        $exception->setError("timeout", CURLE_OPERATION_TIMEOUTED);

        $httpRequest = $this->getRequestMock($this->throwException($exception));

        $httpClient = $this->getHttpClientMock(
            $this->returnValue($httpRequest)
        );

        $validator = new TrueValidator($container);
        $validator->setClient($httpClient);

        $constraint =  new True();
        $context = $this->getMockBuilder('Symfony\Component\Validator\ExecutionContextInterface')->getMock();
        // assert
        $context->expects($this->never())
            ->method('addViolation');

        // act
        $validator->initialize($context);
        $validator->validate('x', $constraint);
    }

    /**
     * @return Container
     */
    private function getContainer() {
        $request = new Request(array(), array(
                'recaptcha_challenge_field'=>'challenge',
                'recaptcha_response_field'=>'response_field',
            ), array(), array(), array(), array(
                'REALIP'=>'1.1.1.1'
            )
        );
        $container = new Container();
        $container->setParameter('ewz_recaptcha.private_key', 'key');
        $container->setParameter('ewz_recaptcha.enabled', 'true');
        $container->set('request', $request);

        return $container;
    }

    /**
     * @param $will
     *
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    public function getRequestMock($will)
    {
        $httpRequest = $this->getMockBuilder('\Guzzle\Http\Message\Request')->disableOriginalConstructor()->getMock();
        $httpRequest->expects($this->once())
            ->method('send')
            ->will($will);
        return $httpRequest;
    }

    protected function getHttpResponse($body)
    {
        $httpResponse = new \Guzzle\Http\Message\Response(200, null, $body);
        return $httpResponse;
    }
    /**
     * @param $will
     *
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    public function getHttpClientMock($will)
    {
        $httpClient = $this->getMockBuilder('\Guzzle\Http\Client')->setMethods(array('post'))->getMock();
        $httpClient->expects($this->once())
            ->method('post')->will(
                $will
            );
        return $httpClient;
    }

}
 