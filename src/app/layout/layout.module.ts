import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import {LayoutComponent} from "./layout/layout.component";
import {HeaderComponent} from "./header/header.component";
import {FooterComponent} from "./footer/footer.component";
import {SidenavComponent} from "./sidenav/sidenav.component";
import {MdbCollapseModule} from "mdb-angular-ui-kit/collapse";
import {RouterModule} from "@angular/router";



@NgModule({
  declarations: [
    LayoutComponent,
    HeaderComponent,
    FooterComponent,
    SidenavComponent
  ],
  imports: [
    CommonModule,
    MdbCollapseModule,
    RouterModule,
  ],

})
export class LayoutModule { }
