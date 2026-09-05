import { TestBed } from '@angular/core/testing';

import { NvdService } from './nvd.service';

describe('NvdService', () => {
  let service: NvdService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(NvdService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
