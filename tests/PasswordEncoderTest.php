<?php
/**
 * This file is part of the Effiana package.
 *
 * (c) Effiana, LTD
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @author Dominik Labudzinski <dominik@labudzinski.com>
 */

use Effiana\PasswordBundle\Security\PasswordEncoder;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Class PasswordEncoderTest
 */
class PasswordEncoderTest extends WebTestCase
{
    public function testEncrypt()
    {
        self::bootKernel();

        // returns the real and unchanged service container
        $container = self::$kernel->getContainer();

        // gets the special container that allows fetching private services
        $container = self::$container;
        $passwordEncoder = $container->get('effiana_password_encoder');
        $encodePassword = $passwordEncoder->encodePassword('test', '123456');
        $this->assertTrue($passwordEncoder->isPasswordValid($encodePassword, 'test', '123456'));



        $longPass = hash('sha512', time()).hash('sha512', time()).hash('sha512', time()).hash('sha512', time());
        $longSalt = hash('sha512', microtime()).hash('sha512', time()).hash('sha512', time()).hash('sha512', microtime());

        $encodePassword = $passwordEncoder->encodePassword($longPass, $longSalt);
        $this->assertTrue($passwordEncoder->isPasswordValid($encodePassword, $longPass, $longSalt));
    }
}
