import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { LocalStorageService } from '../../services/local-storage/local-storage.service';


export const authGuard: CanActivateFn = (route, state) => {
    const router = inject(Router);
    const localStorageService = inject(LocalStorageService);
  
    if (localStorageService.getToken()) {
      return true;
    } else {
      router.navigate(['/login']);
      return false;
    }
};