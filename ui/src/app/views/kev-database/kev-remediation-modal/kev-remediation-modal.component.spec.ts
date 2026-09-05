import { ComponentFixture, TestBed } from '@angular/core/testing';

import { KevRemediationModalComponent } from './kev-remediation-modal.component';

describe('KevRemediationModalComponent', () => {
  let component: KevRemediationModalComponent;
  let fixture: ComponentFixture<KevRemediationModalComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [KevRemediationModalComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(KevRemediationModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
