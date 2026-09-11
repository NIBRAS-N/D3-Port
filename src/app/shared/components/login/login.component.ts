// import { Component } from '@angular/core';
// import { FormBuilder, FormGroup, Validators } from '@angular/forms';
// import { Router } from '@angular/router';
// import { NgxSpinnerService } from 'ngx-spinner';
// import Swal from 'sweetalert2';
// import { OtpResendModel } from '../../shared/models/auth/otp-resend.model';
// import { SharedModule } from '../../shared/modules/shared.module';
// import { AuthService } from '../../shared/services/auth/auth.service';
// import { LocalStorageService } from '../../shared/services/local-storage/local-storage.service';
// import { NotificationService } from '../../shared/services/notification/notification.service';

// @Component({
//   selector: 'app-login',
//   imports: [SharedModule],
//   templateUrl: './login.component.html',
//   styleUrl: './login.component.scss',
// })
// export class LoginComponent {
//   hidePassword = true;
//   loginForm: FormGroup;
//   showPassword = false;
//   showForgotSection = false;

//   togglePassword() {
//     this.showPassword = !this.showPassword;
//   }

//   slides = [
//     {
//       image: '/images/gallary/gallary.jpg', // Path to your actual image
//       title: 'Manage, Monitor, Serve — All in One Place',
//       description:
//         'Handle seamless check-ins and check-outs, oversee room service requests, manage guest details, and streamline operations—right from your dashboard.',
//     },
//     {
//       image: '/images/gallary/gallary.jpg',
//       title: 'Manage, Monitor, Serve — All in One Place',
//       description:
//         'Handle seamless check-ins and check-outs, oversee room service requests, manage guest details, and streamline operations—right from your dashboard.',
//     },
//     {
//       image: '/images/gallary/gallary.jpg',
//       title: 'Manage, Monitor, Serve — All in One Place',
//       description:
//         'Handle seamless check-ins and check-outs, oversee room service requests, manage guest details, and streamline operations—right from your dashboard.',
//     },
//   ];
//   public OtpResendModel: OtpResendModel = new OtpResendModel();

//   constructor(
//     private fb: FormBuilder,
//     private readonly authService: AuthService,
//     private readonly localStorageService: LocalStorageService,
//     private readonly notificationService: NotificationService,
//     private readonly spinner: NgxSpinnerService,
//     private readonly router: Router
//   ) {
//     this.loginForm = this.fb.group({
//       email: ['', [Validators.required, Validators.email]],
//       password: ['', Validators.required],
//     });
//   }

//   ngOnInit(): void {
//     if (
//       this.localStorageService.getSessionUser() &&
//       this.localStorageService.getToken()
//     ) {
//       this.router.navigateByUrl('/dashboard/home');
//     }
//   }

//   public login(): void {
//     if (this.loginForm.valid) {
//       this.spinner.show();
//       const { email, password } = this.loginForm.value;
//       this.authService.login({ email, password }).subscribe({
//         next: (result) => {
//           console.log('login res:', result);
//           this.spinner.hide();
//           this.handleLoggedInUser(result.result);
//         },
//         error: (err) => {
//           this.onError(err);
//         },
//       });
//     }
//   }

//   private onError(error: any) {
//     this.spinner.hide();
//     Swal.fire(`${error.error.message}`);
//     if (error?.error?.message === 'Requested user is not verified.') {
//       this.OtpResendModel.email = this.loginForm.get('email')?.value;
//       this.otpSend();
//     }
//   }

//   private otpSend() {
//     this.spinner.show();
//     if (this.OtpResendModel.email)
//       this.localStorageService.setSignedUpEmail(this.OtpResendModel.email);
//     this.authService.resendOtp(this.OtpResendModel).subscribe({
//       next: (result) => {
//         this.spinner.hide();
//         this.localStorageService.setResendOtpDisabledTimestamp();
//         this.router.navigateByUrl('/auth/verify-otp');
//       },
//       error: (error) => {
//         this.spinner.hide();
//         Swal.fire(`${error.error.message}`);
//         if (error?.error?.message === 'Otp already exists.') {
//           this.router.navigateByUrl('/auth/verify-otp');
//         }
//       },
//     });
//   }

//   private handleLoggedInUser(res: any): void {
//     if (this.localStorageService.getToken()) {
//       this.localStorageService.deleteToken();
//     }
//     if (this.localStorageService.getSessionUser()) {
//       this.localStorageService.clearSessionUser();
//     }

//     this.localStorageService.setToken(res?.accessToken);
//     this.localStorageService.setSessionUser(res?.user);
//     this.localStorageService.setSessionPropertyStaff(
//       res?.user?.propertyStaffs?.[0]
//     );

//     this.notificationService.requestPermissionToNotificationServer(
//       res?.user?.id
//     );

//     this.router.navigateByUrl('/dashboard/home');
//   }

//   toggleForgotPassword() {
//     this.showForgotSection = !this.showForgotSection;
//   }
//   email = '';

//   goBackLogin() {
//     this.showForgotSection = false;
//   }

//   sendResetLink() {
//     const body = {
//       email: this.OtpResendModel.email,
//     };
//     this.authService.resendEmailRequest(body).subscribe({
//       next: (res) => {
//         console.log('Reset email sent successfully:', res);
//         this.clearEmail();
//       },
//       error: (err) => {
//         console.error('Error sending reset email:', err);
//       },
//     });
//   }

//   clearEmail() {
//     this.OtpResendModel.email = null;
//   }
// }
