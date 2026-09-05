import { TestBed } from '@angular/core/testing';

import { EpssService } from './epss.service';

describe('EpssService', () => {
  let service: EpssService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(EpssService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
