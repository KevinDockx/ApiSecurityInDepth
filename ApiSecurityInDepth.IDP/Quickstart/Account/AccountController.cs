// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using ApiSecurityInDepth.IDP.Quickstart.Account;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityServerHost.Quickstart.UI
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local and external accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// </summary>
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly TestUserStore _users;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly IDataProtector _protector;

        public AccountController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IDataProtectionProvider provider,
            TestUserStore users = null)
        {
            // if the TestUserStore is not in DI, then we'll just use the global users collection
            // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)
            _users = users ?? new TestUserStore(TestUsers.Users);

            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _protector = provider.CreateProtector("ApiSecurityInDepth.IDP.DelegationDataBagCookie");
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        #region Postback without delegation
        ///// <summary>
        ///// Handle postback from username/password login
        ///// </summary>
        //[HttpPost]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> Login(LoginInputModel model, string button)
        //{
        //    // check if we are in the context of an authorization request
        //    var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

        //    // the user clicked the "cancel" button
        //    if (button != "login")
        //    {
        //        if (context != null)
        //        {
        //            // if the user cancels, send a result back into IdentityServer as if they 
        //            // denied the consent (even if this client does not require consent).
        //            // this will send back an access denied OIDC error response to the client.
        //            await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

        //            // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
        //            if (context.IsNativeClient())
        //            {
        //                // The client is native, so this change in how to
        //                // return the response is for better UX for the end user.
        //                return this.LoadingPage("Redirect", model.ReturnUrl);
        //            }

        //            return Redirect(model.ReturnUrl);
        //        }
        //        else
        //        {
        //            // since we don't have a valid context, then we just go back to the home page
        //            return Redirect("~/");
        //        }
        //    }

        //    if (ModelState.IsValid)
        //    {
        //        // validate username/password against in-memory store
        //        if (_users.ValidateCredentials(model.Username, model.Password))
        //        {
        //            var user = _users.FindByUsername(model.Username);
        //            await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.SubjectId, user.Username, clientId: context?.Client.ClientId));

        //            // only set explicit expiration here if user chooses "remember me". 
        //            // otherwise we rely upon expiration configured in cookie middleware.
        //            AuthenticationProperties props = null;
        //            if (AccountOptions.AllowRememberLogin && model.RememberLogin)
        //            {
        //                props = new AuthenticationProperties
        //                {
        //                    IsPersistent = true,
        //                    ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
        //                };
        //            };

        //            // issue authentication cookie with subject ID and username
        //            var isuser = new IdentityServerUser(user.SubjectId)
        //            {
        //                DisplayName = user.Username
        //            };

        //            await HttpContext.SignInAsync(isuser, props);

        //            if (context != null)
        //            {
        //                if (context.IsNativeClient())
        //                {
        //                    // The client is native, so this change in how to
        //                    // return the response is for better UX for the end user.
        //                    return this.LoadingPage("Redirect", model.ReturnUrl);
        //                }

        //                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
        //                return Redirect(model.ReturnUrl);
        //            }

        //            // request for a local page
        //            if (Url.IsLocalUrl(model.ReturnUrl))
        //            {
        //                return Redirect(model.ReturnUrl);
        //            }
        //            else if (string.IsNullOrEmpty(model.ReturnUrl))
        //            {
        //                return Redirect("~/");
        //            }
        //            else
        //            {
        //                // user might have clicked on a malicious link - should be logged
        //                throw new Exception("invalid return URL");
        //            }
        //        }

        //        await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId:context?.Client.ClientId));
        //        ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
        //    }

        //    // something went wrong, show form with error
        //    var vm = await BuildLoginViewModelAsync(model);
        //    return View(vm);
        //}
        #endregion


        #region Postback with delegation screen
        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (context.IsNativeClient())
                    {
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                // validate username/password against in-memory store
                if (_users.ValidateCredentials(model.Username, model.Password))
                {
                    var user = _users.FindByUsername(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.SubjectId, user.Username, clientId: context?.Client.ClientId));

                    // write a temp, encrypted cookie with values required for delegation.  Cookie gets cleared on effective signin. 
                    var cookieModel = new DelegationDataBag()
                    {
                        Subject = user.SubjectId,
                        UserName = user.Username,
                        ReturnUrl = model.ReturnUrl ?? "",
                        RememberLogin = model.RememberLogin
                    };
                    var cookieDataInJson = JsonConvert.SerializeObject(cookieModel);
                    var protectedData = _protector.Protect(cookieDataInJson);
                    var options = new CookieOptions
                    {
                        Expires = DateTime.Now.AddMinutes(15)
                    };

                    Response.Cookies.Append("DelegationDataBagCookie", protectedData, options);

                    return await ExecuteDelegationWhenApplicable(user.SubjectId, user.Username, model.ReturnUrl, model.RememberLogin);

                    // rest of code removed - is now handled after the delegation screen 
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.Client.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }
        #endregion

        private async Task<RedirectResult> ExecuteDelegationWhenApplicable(string subject,
          string username, string returnUrl, bool rememberLogin)
        {
            // are there users this user can act as?  This is where you'd write custom logic
            // to choose which users the user is allowed to act as.  For the demo
            // this is possible for everyone
            var usersToActAs = TestUsers.Users.Where(u => u.SubjectId != subject);

            if (usersToActAs.Any())
            {
                // redirect to the user selection page.  
                var redirectToUserSelectionUrl = Url.Action("Delegate");

                if (_interaction.IsValidReturnUrl(returnUrl) || (Url.IsLocalUrl(returnUrl)))
                {
                    return Redirect(redirectToUserSelectionUrl);
                }
            }

            // else, redirect
            return await SetSigninCookieAndRedirect(subject, username, returnUrl, rememberLogin);
        }

        /// <summary>
        /// Show delegation page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Delegate()
        {
            // get the required values from the temp cookie
            var protectedCookieValue = Request.Cookies["DelegationDataBagCookie"];
            if (protectedCookieValue == null)
            {
                return RedirectToAction("Login", "Account");
            }
            var cookieDataInJson = _protector.Unprotect(protectedCookieValue);
            var cookieData = JsonConvert.DeserializeObject<DelegationDataBag>(cookieDataInJson);

            // build a model  
            var vm = await BuildDelegationViewModel(cookieData.ReturnUrl, cookieData.Subject);
            return View(vm);
        }

        /// <summary>
        /// Handle postback from delegation
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delegate(LoginDelegationInputViewModel model, string button)
        {
            // get the required values from the temp cookie
            var protectedCookieValue = Request.Cookies["DelegationDataBagCookie"];
            if (protectedCookieValue == null)
            {
                return RedirectToAction("Login", "Account");
            }

            var cookieDataInJson = _protector.Unprotect(protectedCookieValue);
            var cookieData = JsonConvert.DeserializeObject<DelegationDataBag>(cookieDataInJson);

            if (ModelState.IsValid)
            {
                string impersonateSubject = null;
                if (button != cookieData.Subject)
                {
                    var actors = TestUsers.Users.Where(u => u.SubjectId != cookieData.Subject);
                    impersonateSubject = actors.Where(a => a.SubjectId == button).FirstOrDefault()?.SubjectId;
                }

                // do something with the actor and sign in.
                return await SetSigninCookieAndRedirect(cookieData.Subject,
                    cookieData.UserName, cookieData.ReturnUrl, cookieData.RememberLogin, impersonateSubject);
            }

            // something went wrong 
            var vm = await BuildDelegationViewModel(cookieData.ReturnUrl,
                cookieData.Subject);

            return View(vm);
        }

        private async Task<RedirectResult> SetSigninCookieAndRedirect(string subject,
            string username, string returnUrl, bool rememberLogin, string userToActAsSubject = null)
        {
            // only set explicit expiration here if user chooses "remember me". 
            // otherwise we rely upon expiration configured in cookie middleware.
            AuthenticationProperties props = null;
            if (AccountOptions.AllowRememberLogin && rememberLogin)
            {
                props = new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                };
            };

            if ((string.IsNullOrEmpty(userToActAsSubject)) || (subject == userToActAsSubject))
            {
                // no user selected
                // issue authentication cookie with original subject ID and username
                var isuser = new IdentityServerUser(subject)
                {
                    DisplayName = username
                };

                await HttpContext.SignInAsync(isuser, props);                 
            }
            else
            {
                // user to act as selected - add an additional claim
                var userToActAs = TestUsers.Users.First(u => u.SubjectId == userToActAsSubject);

                // create the actor claim (= the "real" user, ie: the actor). 
                // only add the subject at this time, the other values are filled out via a custom
                // profile service (as we need to know the selected scopes to correctly fill out the claims)                

                var actorBuilder = new StringBuilder();
                actorBuilder.Append(@"{""sub"":""");
                actorBuilder.Append(subject);
                actorBuilder.Append(@"""}");

                // sign in as the selected user, passing through the "real" user as actor
                var isuser = new IdentityServerUser(userToActAsSubject)
                {
                    DisplayName = userToActAs.Username,
                    AdditionalClaims = new List<Claim>() {
                                            new Claim("act",
                                            actorBuilder.ToString(),
                                            IdentityServer4.IdentityServerConstants.ClaimValueTypes.Json) }
                };

                await HttpContext.SignInAsync(isuser, props);                 
            }
             
            // TODO pass through "isnativeclient"
            //if (context != null)
            //{
            //    if (context.IsNativeClient())
            //    {
            //        // The client is native, so this change in how to
            //        // return the response is for better UX for the end user.
            //        return this.LoadingPage("Redirect", returnUrl);
            //    }

            //    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
            //    return Redirect(returnUrl);
            //}

            // request for a local page
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else if (string.IsNullOrEmpty(returnUrl))
            {
                return Redirect("~/");
            }
            else
            {
                // user might have clicked on a malicious link - should be logged
                throw new Exception("invalid return URL");
            } 
        }

        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await HttpContext.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }


        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginDelegationInputViewModel> BuildDelegationViewModel(
          string returnUrl, string subject)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

            // get the users this user can act as
            var usersToActAs = TestUsers.Users.Where(u => u.SubjectId != subject);
            var potentialUsers = new List<LocalUser>();

            foreach (var userToActAs in usersToActAs)
            {
                potentialUsers.Add(new LocalUser()
                {
                    Name = $"{userToActAs.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.GivenName)?.Value} " +
                    $"{userToActAs.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.FamilyName)?.Value}",
                    Subject = userToActAs.SubjectId
                });
            }

            var currentUserData = TestUsers.Users.FirstOrDefault(u => u.SubjectId == subject);
            var currentUser = new LocalUser()
            {
                Name = $"{currentUserData.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.GivenName)?.Value} " +
                $"{currentUserData.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.FamilyName)?.Value}",
                Subject = subject,
            };

            return new LoginDelegationInputViewModel
            {
                PotentialUsers = potentialUsers,
                CurrentUser = currentUser
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}
