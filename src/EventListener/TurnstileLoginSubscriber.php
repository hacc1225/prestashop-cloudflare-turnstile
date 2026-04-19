<?php

namespace PixelCloudflareTurnstile\EventListener;

use Module;
use Pixel_cloudflare_turnstile;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class TurnstileLoginSubscriber implements EventSubscriberInterface
{
    /**
     * @var UrlGeneratorInterface
     */
    private $router;

    public function __construct(UrlGeneratorInterface $router)
    {
        $this->router = $router;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            // Priority 16: After RouterListener (32) but BEFORE Symfony Security (8)
            KernelEvents::REQUEST => ['onKernelRequest', 16],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        if (!$request->isMethod('POST')) {
            return;
        }

        $route = $request->attributes->get('_route');
        
        // 1. Detect Login Submission
        $isLogin = ($route === 'admin_login' && $request->request->has('submit_login'));

        // 2. Detect Forgot Password Submission
        $forgotData = $request->request->all('request_password_reset');
        $isForgot = ($route === 'admin_request_password_reset' && !empty($forgotData));

        if (!$isLogin && !$isForgot) {
            return;
        }

        /** @var Pixel_cloudflare_turnstile $module */
        $module = Module::getInstanceByName('pixel_cloudflare_turnstile');
        if (!$module || !$module->active) {
            return;
        }

        if (($isLogin && $module->isAvailable($module::FORM_ADMIN_LOGIN)) ||
            ($isForgot && $module->isAvailable($module::FORM_ADMIN_FORGOT))) {

            if (!Pixel_cloudflare_turnstile::turnstileValidation()) {
                $error = !empty(Pixel_cloudflare_turnstile::$validationError) 
                    ? Pixel_cloudflare_turnstile::$validationError 
                    : $module->getTranslator()->trans('Security validation error', [], 'Modules.Pixelcloudflareturnstile.Shop');
                
                $request->getSession()->getFlashBag()->add('error', $error);

                // Redirect to login page for both cases, without #forgotten_password fragment
                $url = $this->router->generate('admin_login');
                $event->setResponse(new RedirectResponse($url));
            }
        }
    }
}
