// import { Injectable } from '@angular/core';
// import { BehaviorSubject, map, Observable } from 'rxjs';
// import { UrlEnum } from '../../enums/url.enum';
// import { OtpResendModel } from '../../models/auth/otp-resend.model';
// import { HttpRequestService } from '../http-request/http-request.service';
// import { LocalStorageService } from '../local-storage/local-storage.service';
// import { NotificationService } from '../notification/notification.service';
// import { UtilitiesService } from '../utilities/utilities.service';
// import { ResetPasswordModel } from '../../models/auth/reset-password.model';
// import { RegisterBodyModel } from '../../models/auth/register.model';
// import { OtpBodyModel } from '../../models/auth/otp.model';

// @Injectable({
//   providedIn: 'root',
// })
// export class AuthService {
//   private loginApi = UrlEnum.OTITHI_AUTH;

//   private loggedInSubject = new BehaviorSubject<boolean>(false);

//   isLoggedIn$ = this.loggedInSubject.asObservable();

//   constructor(
//     private readonly httpRequestService: HttpRequestService,
//     private readonly utilitiesService: UtilitiesService,
//     private readonly localStorageService: LocalStorageService,
//     private readonly notificationService: NotificationService
//   ) {
//     const hasToken = !!this.localStorageService.getToken();
//     this.loggedInSubject.next(hasToken);
//   }

//   public isLoggedIn(): boolean {
//     return this.localStorageService.getToken() ? true : false;
//   }

//   public login(body: any): Observable<any> {
//     return this.httpRequestService.post(`${this.loginApi}/auth/login`, body, {
//       skipAuth: true,
//     });
//   }

//   public setLoggedIn(value: boolean) {
//     // for  direct booking site
//     this.loggedInSubject.next(value);
//   }

//   public logout() {
//     this.localStorageService.deleteToken();
//     this.localStorageService.clearSessionUser();

//     this.notificationService.unRegisterNotificationServer();
//     this.setLoggedIn(false);
//   }

//   public resendOtp(body: OtpResendModel): Observable<any> {
//     return this.httpRequestService
//       .post(`${this.loginApi}/otp/resend`, body, { skipAuth: true })
//       .pipe(map((x: any) => this.utilitiesService.responseHandler(x)));
//   }

//   public updateUser(userId: string, body: any): Observable<any> {
//     return this.httpRequestService
//       .patch(`${this.loginApi}/user/update/${userId}`, body)
//       .pipe(map((x: any) => this.utilitiesService.responseHandler(x)));
//   }

//   public updatePassword(
//     userId: string,
//     body: {
//       oldPassword: string;
//       newPassword: string;
//       confirmPassword: string;
//     }
//   ): Observable<any> {
//     return this.httpRequestService
//       .post(`${this.loginApi}/user/update-password/${userId}`, body)
//       .pipe(map((x: any) => this.utilitiesService.responseHandler(x)));
//   }

//   public resendEmailRequest(body: OtpResendModel): Observable<any> {
//     return this.httpRequestService
//       .post(`${this.loginApi}/auth/request-password-reset`, body, {
//         skipAuth: true,
//       })
//       .pipe(map((x: any) => this.utilitiesService.responseHandler(x)));
//   }

//   public resetPassword(body: ResetPasswordModel): Observable<any> {
//     return this.httpRequestService
//       .post(`${this.loginApi}/auth/password-reset`, body, { skipAuth: true })
//       .pipe(map((x: any) => this.utilitiesService.responseHandler(x)));
//   }
//   public registerByEmail(body: RegisterBodyModel): Observable<any> {
//     return this.httpRequestService
//       .post(`${this.loginApi}/auth/register`, body, {
//         skipAuth: true,
//       })
//       .pipe(map((x: any) => this.utilitiesService.responseHandler(x)));
//   }
//   public verifyOtp(body: OtpBodyModel): Observable<any> {
//     return this.httpRequestService
//       .post(`${this.loginApi}/otp/verify-otp`, body, {
//         skipAuth: true,
//       })
//       .pipe(map((x: any) => this.utilitiesService.responseHandler(x)));
//   }
// }
