import { Component, OnInit } from '@angular/core';
import {ToastrService} from "ngx-toastr";
import {MdbModalService} from "mdb-angular-ui-kit/modal";
import {debounceTime, distinctUntilChanged, Subject} from "rxjs/Observable";
import {EPSS, EpssService} from "../../services/epss.service";

@Component({
  selector: 'app-epss-database',
  templateUrl: './epss-database.component.html',
  styleUrls: ['./epss-database.component.scss']
})
export class EpssDatabaseComponent implements OnInit {
  public epssData: EPSS[] = [];
  public isIngesting: boolean = false;
  public isLoading: boolean = true;

  // Pagination Properties
  public currentPage: number = 0;
  public pageSize: number = 15;
  public totalElements: number = 0;

  searchTerm: string = '';
  private searchSubject = new Subject<string>();

  // Logic helpers for the UI
  getRiskClass(score: number): string {
    if (score > 0.1) return 'bg-danger';
    if (score > 0.01) return 'bg-warning';
    return 'bg-success';
  }

  getRiskLabel(score: number): string {
    // Over 10% is effectively a "When, not If" scenario in global telemetry
    if (score > 0.1) return 'Critical Probability';

    // 5% to 10% is very high compared to the 0.001% average
    if (score > 0.05) return 'High Probability';

    // 1% to 5% is elevated
    if (score > 0.01) return 'Elevated';

    return 'Low Risk';
  }

  getRiskBadgeClass(score: number): string {
    if (score > 0.1) return 'bg-danger-soft text-danger fw-bold';
    if (score > 0.05) return 'bg-orange-soft text-orange'; // You'd need a custom 'orange' class
    if (score > 0.01) return 'bg-warning-soft text-warning text-dark';
    return 'bg-success-soft text-success';
  }

  constructor(
    private epssService: EpssService,
    private toastr: ToastrService,
    private modalService: MdbModalService
  ) {
    // Setup debounced search
    this.searchSubject.pipe(
      debounceTime(400), // Wait 400ms after typing stops
      distinctUntilChanged() // Only search if text actually changed
    ).subscribe(value => {
      this.searchTerm = value;
      this.currentPage = 0; // Reset to page 1 on new search
      this.loadEpssData();
    });
  }

  ngOnInit(): void {
    this.loadEpssData();
  }

  /**
   * Fetches paged KEV data from the Spring Boot backend
   */
  loadEpssData(): void {
    this.isLoading = true;
    this.epssService.getEpssData(this.currentPage, this.pageSize, this.searchTerm).subscribe({
      next: (res) => {
        this.epssData = res.content;
        this.totalElements = res.totalElements;
        this.isLoading = false;

        // Optional: Inform the user if they manually clicked refresh
        if (this.searchTerm === '') {
          this.toastr.success('Exploit Prediction Scoring table updated', 'Refreshed', {
            timeOut: 2000,
            positionClass: 'toast-bottom-right'
          });
        }
      },
      error: (err) => {
        this.isLoading = false;
        this.toastr.error('Failed to sync with local database', 'Update Error');
      }
    });
  }

  /**
   * Triggers the /api/kev/ingest endpoint
   */
  onIngest(): void {
    if (this.isIngesting) return;

    this.isIngesting = true;
    this.toastr.info('Starting Exploit Prediction Scoring Ingestion...', 'Sync in Progress');

    this.epssService.ingestEpss().subscribe({
      next: (res) => {
        this.toastr.success('Successfully synced', 'Ingestion Complete');
        this.isIngesting = false;
        this.currentPage = 0; // Reset to first page to see new data
        this.loadEpssData();
      },
      error: (err) => {
        this.isIngesting = false;
        this.toastr.error('EPSS API might be unreachable', 'Ingestion Failed');
      }
    });
  }

  onSearch(event: any): void {
    this.searchSubject.next(event.target.value);
  }

  onPageChange(page: number): void {
    this.currentPage = page;
    this.loadEpssData();
  }

  protected readonly math = Math;
}
