import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SbomHistoryModalComponent } from './sbom-history-modal.component';

describe('SbomHistoryModalComponent', () => {
  let component: SbomHistoryModalComponent;
  let fixture: ComponentFixture<SbomHistoryModalComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SbomHistoryModalComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SbomHistoryModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
