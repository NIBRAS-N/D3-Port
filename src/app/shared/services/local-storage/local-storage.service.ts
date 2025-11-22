import { Injectable } from '@angular/core';
import { JwtHelperService } from '@auth0/angular-jwt';
import * as CryptoJS from 'crypto-js';
import { CookieService } from 'ngx-cookie-service';
import { UserTypeEnum } from '../../enums/user-type.enum';
const jwtHelper = new JwtHelperService();
// import { environment } from '../../../../environments/environment';

const environment = { envName: 'development' };

@Injectable({
  providedIn: 'root',
})
export class LocalStorageService {
  secretKey = 'bracWashProject2023#DevelopedBy@BMQA@2023_TonmoyrUdra';
  secretKey2 = 'lol';
  constructor(private cookieService: CookieService) {}

  encrypt(value: string): string {
    //return value;
    if (environment.envName === 'development') {
      return value;
    } else {
      return CryptoJS.AES.encrypt(value, this.secretKey.trim()).toString();
    }
  }

  decrypt(textToDecrypt: string) {
    if (environment.envName === 'development') {
      return textToDecrypt;
    } else {
      if (textToDecrypt === null) {
        return textToDecrypt;
      } else {
        return CryptoJS.AES.decrypt(
          textToDecrypt,
          this.secretKey.trim()
        ).toString(CryptoJS.enc.Utf8);
      }
    }
  }

  setNgoInLocalStorage(ngo: any) {
    localStorage.setItem(
      'current_selected_ngo',
      this.encrypt(JSON.stringify(ngo))
    );
  }

  getNgoInLocalStorage() {
    return JSON.parse(
      this.decrypt(
        localStorage.getItem('current_selected_ngo') as string
      ) as string
    );
  }

  setProjectInLocalStorage(program: any) {
    localStorage.setItem(
      'current_selected_project',
      this.encrypt(JSON.stringify(program))
    );
  }

  getProjectFromLocalStorage() {
    return JSON.parse(
      this.decrypt(
        localStorage.getItem('current_selected_project') as string
      ) as string
    );
  }

  deleteProjectFromLocalStorage() {
    this.clearLocalStorageByKey('current_selected_project');
  }

  getToken() {
    return this.cookieService.get('token');
    // return localStorage.getItem('token');
  }

  setToken(token: string) {
    this.cookieService.set('token', token);
    //this.cookieService.set('token2', token, null, '../',);
    // localStorage.setItem('token', token);
  }

  deleteToken() {
    this.cookieService.delete('token');
  }

  setSessionUserFromToken(token: string) {
    try {
      const tokenDecode = jwtHelper.decodeToken(token);
      delete tokenDecode.iat;
      delete tokenDecode.iss;
      localStorage.setItem('sessionUser', JSON.stringify(tokenDecode));
      return true;
    } catch (error) {
      return false;
    }
  }

  setSessionUser(user: any) {
    this.setLocalStorage('sessionUser', user);
  }

  getSessionUser(): any {
    return this.getLocalStorage('sessionUser');
  }

  public setSessionPropertyStaff(propertyStaff: any) {
    this.setLocalStorage('sessionPropertyStaff', propertyStaff);
  }

  public getSessionPropertyStaff(): any {
    return this.getLocalStorage('sessionPropertyStaff');
  }

  static getSessionUserStatic(): any {
    const sessionUser = localStorage.getItem('sessionUser') as string;
    if (environment.envName === 'development') {
      return JSON.parse(sessionUser);
    } else {
      if (sessionUser === null) {
        return JSON.parse(sessionUser);
      } else {
        return CryptoJS.AES.decrypt(
          sessionUser,
          'bracWashProject2023#DevelopedBy@BMQA@2023_TonmoyrUdra'.trim()
        ).toString(CryptoJS.enc.Utf8);
      }
    }
  }

  static getCurrentSelectedNgoStatic(): any {
    const selectedNgo = localStorage.getItem('current_selected_ngo') as string;
    if (environment.envName === 'development') {
      return JSON.parse(selectedNgo);
    } else {
      if (selectedNgo === null) {
        return JSON.parse(selectedNgo);
      } else {
        return CryptoJS.AES.decrypt(
          selectedNgo,
          'bracWashProject2023#DevelopedBy@BMQA@2023_TonmoyrUdra'.trim()
        ).toString(CryptoJS.enc.Utf8);
      }
    }
  }

  public getSessionUserRole() {
    return this.getSessionUser().role;
  }

  public getIsNgoAdmin(): boolean {
    const role = this.getSessionUserRole();
    return (
      this.getSessionUserRole().short_form === 'admin' ||
      this.getSessionUserRole().short_form === 'donor'
    );
  }

  public getIsSuperAdmin(): boolean {
    const role = this.getSessionUserRole();
    return this.getSessionUserRole().short_form === 'system_admin';
  }
  public isAdmin(): boolean {
    return this.getSessionUser()?.type === UserTypeEnum.ADMIN;
  }

  public isUser(): boolean {
    return this.getSessionUser()?.type === UserTypeEnum.USER;
  }

  public clearSessionUser() {
    this.clearLocalStorageByKey('sessionUser');
    this.clearLocalStorageByKey('sessionPropertyStaff');
    this.clearLocalStorageByKey('isNotificationRegistered');
  }

  setBracToken(token: string) {
    localStorage.setItem('multipass', JSON.stringify(token));
  }

  getBracToken() {
    return JSON.parse(localStorage.getItem('multipass')!);
  }

  getUserInfo() {
    return JSON.parse(localStorage.getItem('user')!);
  }

  setUserInfo(user: string) {
    localStorage.setItem('user', JSON.stringify(user));
  }

  getACLMenuInfo() {
    return JSON.parse(this.decrypt(localStorage.getItem('acl') as string));
  }

  setACLMenuInfo(data: any) {
    localStorage.setItem('acl', this.encrypt(JSON.stringify(data)));
  }

  getControls() {
    return JSON.parse(this.decrypt(localStorage.getItem('controls') as string));
  }

  setControls(data: any) {
    localStorage.setItem('controls', this.encrypt(JSON.stringify(data)));
  }

  getSections() {
    return JSON.parse(this.decrypt(localStorage.getItem('sections') as string));
  }

  setSection(data: any) {
    localStorage.setItem('sections', this.encrypt(JSON.stringify(data)));
  }

  getSelectedMenuInfo() {
    return JSON.parse(
      this.decrypt(localStorage.getItem('selectedMenu') as string)
    );
  }

  setSelectedMenuInfo(data: any) {
    localStorage.setItem('selectedMenu', this.encrypt(JSON.stringify(data)));
  }

  public setSignedUpEmail(email: string) {
    this.setLocalStorage('signedUpEmail', email);
  }

  public getSignedUpEmail() {
    return this.getLocalStorage('signedUpEmail');
  }

  public clearSignedUpEmail() {
    this.clearLocalStorageByKey('signedUpEmail');
  }

  public setResendOtpDisabledTimestamp() {
    const now = new Date().getTime();
    this.setLocalStorage('resendOtpDisabledTimestamp', now);
  }

  public getResendOtpDisabledTimestamp() {
    return this.getLocalStorage('resendOtpDisabledTimestamp');
  }

  public clearResendOtpDisabledTimestamp() {
    this.clearLocalStorageByKey('resendOtpDisabledTimestamp');
  }

  public setIsNotificationRegistered(isNotificationRegistered: 'yes' | 'no') {
    this.setLocalStorage('isNotificationRegistered', isNotificationRegistered);
  }

  public getIsNotificationRegistered() {
    const isNotificationRegistered = this.getLocalStorage(
      'isNotificationRegistered'
    );

    if (isNotificationRegistered === 'yes') {
      return true;
    } else {
      return false;
    }
  }

  public clearIsNotificationRegistered() {
    this.clearLocalStorageByKey('isNotificationRegistered');
  }

  public setLocalStorage(key: string, data: any) {
    try {
      const encryptedData = this.encrypt(JSON.stringify(data));
      localStorage.setItem(key, encryptedData);
    } catch (error) {
      console.error(
        `Failed to set item in localStorage for key: ${key}`,
        error
      );
    }
  }

  public getLocalStorage(key: string) {
    try {
      const storedData = localStorage.getItem(key);
      if (storedData === null) {
        return '';
      }

      const decryptedData = this.decrypt(storedData);
      return JSON.parse(decryptedData);
    } catch (error) {
      console.error(
        `Failed to get and parse item from localStorage for key: ${key}`,
        error
      );
      return '';
    }
  }

  public clearLocalStorageByKey(key: string) {
    try {
      localStorage.removeItem(key);
    } catch (error) {
      console.error(
        `Failed to remove item from localStorage for key: ${key}`,
        error
      );
    }
  }

  // encryptObjectUrl(obj: object, key: string): string {
  //   console.log('encryption', key);
  //   const jsonString = JSON.stringify(obj);
  //   const encrypted = CryptoJS.AES.encrypt(
  //     jsonString,
  //     CryptoJS.enc.Utf8.parse(key),
  //     {
  //       mode: CryptoJS.mode.ECB,
  //       padding: CryptoJS.pad.Pkcs7,
  //     }
  //   ).toString();

  //   return encodeURIComponent(encrypted);
  // }

  public encryptObjectUrl(obj: any): string {
    const jsonString = JSON.stringify(obj);

    const encrypted = CryptoJS.AES.encrypt(
      jsonString,
      this.secretKey.trim()
    ).toString();
    // const encrypted = CryptoJS.AES.encrypt(
    //   jsonString,
    //   CryptoJS.enc.Utf8.parse(key.trim()),
    //   {
    //     mode: CryptoJS.mode.ECB,
    //     padding: CryptoJS.pad.Pkcs7,
    //   }
    // );

    const base64String = encrypted.toString();
    return encodeURIComponent(base64String);
  }

  public decryptObjectUrl(encryptedString: string, key?: string): any {
    try {
      const decodedString = decodeURIComponent(encryptedString);

      // const decrypted = CryptoJS.AES.decrypt(
      //   decodedString,
      //   CryptoJS.enc.Utf8.parse(key.trim()),
      //   {
      //     mode: CryptoJS.mode.ECB,
      //     padding: CryptoJS.pad.Pkcs7,
      //   }
      // );

      const decrypted = CryptoJS.AES.decrypt(
        decodedString,
        (key || this.secretKey).trim()
      ).toString(CryptoJS.enc.Utf8);
      // Convert decrypted data to UTF-8 string
      // const jsonString = decrypted.toString(CryptoJS.enc.Utf8);

      // if (!jsonString) {
      //   throw new Error('Decryption failed, empty output');
      // }

      return JSON.parse(decrypted);
    } catch (error) {
      // console.error('Decryption failed:', error);
      return null;
    }
  }
}
