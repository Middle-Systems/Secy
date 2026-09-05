import { TestBed } from '@angular/core/testing';

import { KevService } from './kev.service';

describe('KevService', () => {
  let service: KevService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(KevService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
