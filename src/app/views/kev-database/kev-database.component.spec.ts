import { ComponentFixture, TestBed } from '@angular/core/testing';

import { KevDatabaseComponent } from './kev-database.component';

describe('KevDatabaseComponent', () => {
  let component: KevDatabaseComponent;
  let fixture: ComponentFixture<KevDatabaseComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [KevDatabaseComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(KevDatabaseComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
