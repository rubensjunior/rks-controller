/*!
 App Connect Bootstrap 5 Offcanvas
 Version: 2.0.1
 (c) 2024 Wappler.io
 @build 2024-06-19 12:06:49
 */
dmx.Component("bs5-offcanvas",{initialData:{visible:!1},attributes:{show:{type:Boolean,default:!1},backdrop:{type:[Boolean,String],default:!0},nokeyboard:{type:Boolean,default:!1},scroll:{type:Boolean,default:!1}},methods:{toggle(){requestAnimationFrame((()=>this._instance.toggle()))},show(){requestAnimationFrame((()=>this._instance.show()))},hide(){requestAnimationFrame((()=>this._instance.hide()))}},events:{show:Event,shown:Event,hide:Event,hidden:Event},init(s){s.addEventListener("show.bs.offcanvas",this.dispatchEvent.bind(this,"show")),s.addEventListener("shown.bs.offcanvas",this.dispatchEvent.bind(this,"shown")),s.addEventListener("hide.bs.offcanvas",this.dispatchEvent.bind(this,"hide")),s.addEventListener("hidden.bs.offcanvas",this.dispatchEvent.bind(this,"hidden")),s.addEventListener("show.bs.offcanvas",(()=>this.set("visible",!0))),s.addEventListener("hidden.bs.offcanvas",(()=>this.set("visible",!1))),s.classList.toggle("show",this.props.show),this.set("visible",this.props.show);let t=this.props.backdrop;"static"!=t&&(t="false"!=t),this._instance=new bootstrap.Offcanvas(s,{backdrop:t,keyboard:!this.props.nokeyboard,scroll:this.props.scroll})},destroy(){this._instance.dispose()},performUpdate(s){s.has("show")&&(this.$node.classList.toggle("show",this.props.show),this.set("visible",this.props.show))}});
//# sourceMappingURL=dmxBootstrap5Offcanvas.js.map
