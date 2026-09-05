import { Component, OnInit } from '@angular/core';
import { MdbModalRef, MdbModalService } from 'mdb-angular-ui-kit/modal';
import {VulnerabilityDetailsComponent} from "../vulnerability-details/vulnerability-details.component";
import {SBOM, SBOMComponent} from "../../../services/product.service";

@Component({
  selector: 'app-sbom-history-modal',
  templateUrl: './sbom-history-modal.component.html',
  styleUrls: ['./sbom-history-modal.component.scss']
})
export class SbomHistoryModalComponent implements OnInit {
  product: any;

  constructor(
    public modalRef: MdbModalRef<SbomHistoryModalComponent>,
    private modalService: MdbModalService
  ) {}

  ngOnInit(): void {
    if (this.product?.sboms) {
      // Sort by uploadDate descending
      this.product.sboms.sort((a: SBOM, b: SBOM) =>
        new Date(b.uploadDate).getTime() - new Date(a.uploadDate).getTime()
      );
    }
  }

  calculateTotalFindings(sbom: SBOM): number {
    if (!sbom.components) return 0;
    return sbom.components.reduce((total: number, component: SBOMComponent) => {
      return total + (component.vulnerabilityAlerts?.length || 0);
    }, 0);
  }

  /**
   * Deep scan through components to find actionable alerts (KEV or high EPSS)
   */
  calculateActionableFindings(sbom: SBOM): number {
    if (!sbom.components) return 0;
    return sbom.components.reduce((total: number, component: SBOMComponent) => {
      const actionableInComponent = component.vulnerabilityAlerts?.filter(alert => {
        const hasKev = !!alert.vulnerability?.kev;
        const highEpss = (alert.vulnerability?.epss?.epss ?? 0) > 0.1;
        return hasKev || highEpss;
      }).length || 0;

      return total + actionableInComponent;
    }, 0);
  }

  viewDetails(sbomId: string): void {
    this.modalService.open(VulnerabilityDetailsComponent, {
      modalClass: 'modal-xl modal-dialog-centered',
      data: { sbomId: sbomId }
    });
  }
}
