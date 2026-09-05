import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EpssDatabaseComponent } from './epss-database.component';

describe('EpssDatabaseComponent', () => {
  let component: EpssDatabaseComponent;
  let fixture: ComponentFixture<EpssDatabaseComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EpssDatabaseComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(EpssDatabaseComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
