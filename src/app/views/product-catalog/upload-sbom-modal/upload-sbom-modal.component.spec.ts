import { ComponentFixture, TestBed } from '@angular/core/testing';

import { UploadSbomModalComponent } from './upload-sbom-modal.component';

describe('UploadSbomModalComponent', () => {
  let component: UploadSbomModalComponent;
  let fixture: ComponentFixture<UploadSbomModalComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UploadSbomModalComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(UploadSbomModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
