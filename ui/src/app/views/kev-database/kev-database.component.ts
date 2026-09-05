import { Component, OnInit } from '@angular/core';
import { ToastrService } from 'ngx-toastr';
import {KEV, KevService} from "../../services/kev.service";
import {MdbModalRef, MdbModalService} from "mdb-angular-ui-kit/modal";
import {KevRemediationModalComponent} from "./kev-remediation-modal/kev-remediation-modal.component";
import {debounceTime, distinctUntilChanged, Subject} from "rxjs"; // Optional: for SaaS-style notifications

@Component({
  selector: 'app-kev-database',
  standalone: false,
  templateUrl: './kev-database.component.html',
  styleUrls: ['./kev-database.component.scss']
})
export class KevDatabaseComponent implements OnInit {
  // Data and State Management
  public kevData: KEV[] = [];
  public isIngesting: boolean = false;
  public isLoading: boolean = true;

  // Pagination Properties
  public currentPage: number = 0;
  public pageSize: number = 15;
  public totalElements: number = 0;

  searchTerm: string = '';
  private searchSubject = new Subject<string>();

  public math = Math;

  modalRef: MdbModalRef<KevRemediationModalComponent> | null = null;

  constructor(
    private kevService: KevService,
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
      this.loadKevData();
    });
  }

  ngOnInit(): void {
    this.loadKevData();
  }

  /**
   * Fetches paged KEV data from the Spring Boot backend
   */
  loadKevData(): void {
    this.isLoading = true;
    this.kevService.getKevEntries(this.currentPage, this.pageSize, this.searchTerm).subscribe({
      next: (res) => {
        this.kevData = res.content;
        this.totalElements = res.totalElements;
        this.isLoading = false;

        // Optional: Inform the user if they manually clicked refresh
        if (this.searchTerm === '') {
          this.toastr.success('Threat Intelligence table updated', 'Refreshed', {
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
    this.toastr.info('Starting CISA KEV Ingestion...', 'Sync in Progress');

    this.kevService.ingestKev().subscribe({
      next: (res) => {
        this.toastr.success('Successfully synced with CISA', 'Ingestion Complete');
        this.isIngesting = false;
        this.currentPage = 0; // Reset to first page to see new data
        this.loadKevData();
      },
      error: (err) => {
        this.isIngesting = false;
        this.toastr.error('CISA API might be unreachable', 'Ingestion Failed');
      }
    });
  }

  onSearch(event: any): void {
    this.searchSubject.next(event.target.value);
  }

  onPageChange(page: number): void {
    this.currentPage = page;
    this.loadKevData();
  }

  /**
   * Detailed view for "Required Actions"
   */
  viewRemediationSteps(entry: KEV): void {
    // 2. Assign the result of .open() to this.modalRef
    this.modalRef = this.modalService.open(KevRemediationModalComponent, {
      data: { entry: entry }, // This passes the KEV object to the modal
      modalClass: 'modal-lg modal-dialog-centered'
    });

    // Optional: Do something when the modal closes
    this.modalRef.onClose.subscribe((message: any) => {
      console.log('Modal closed with message:', message);
    });
  }

}
