import { Component } from '@angular/core';
import {KEV} from "../../../services/kev.service";
import {MdbModalRef} from "mdb-angular-ui-kit/modal";
import {ToastrService} from "ngx-toastr";

@Component({
  selector: 'app-kev-remediation-modal',
  standalone: false,
  templateUrl: './kev-remediation-modal.component.html',
  styleUrl: './kev-remediation-modal.component.scss'
})
export class KevRemediationModalComponent {
  entry: KEV | null = null;

  constructor(public modalRef: MdbModalRef<KevRemediationModalComponent>, private toastr: ToastrService) {}

  copyActions(): void {
    if (this.entry?.requiredActions) {
      navigator.clipboard.writeText(this.entry.requiredActions);
      this.toastr.success('Remediation steps copied to clipboard', 'Success');
    }
  }
}
