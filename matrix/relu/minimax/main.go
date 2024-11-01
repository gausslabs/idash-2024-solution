package main

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"

	"app/utils"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/utils/bignum"

	"github.com/vdobler/chart"
	"github.com/vdobler/chart/imgg"
)

func main() {

	Coeffs := hefloat.GenMinimaxCompositePolynomial(512, 3, 10, []int{63}, bignum.Sign)

	fmt.Println("COEFFICIENTS:")
	fmt.Printf("{\n")
	for i := range Coeffs {
		hefloat.PrettyPrintCoefficients(15, Coeffs[i], true, false, false)
	}
	fmt.Printf("},\n")

	coeffs := make([][]float64, len(Coeffs))
	for i := range coeffs {
		coeffs[i] = make([]float64, len(Coeffs[i]))
		for j := range coeffs[i] {
			coeffs[i][j], _ = Coeffs[i][j].Float64()
		}
	}

	hminimax := func(x float64) (y float64) {
		sign := utils.CompositeEval(coeffs, -1, 1, x)
		return (x*sign + x) / 2
	}

	dumper := NewDumper("sign", 1, 1, 4*1080, 4*720)

	fF64 := func(x float64) (y float64) {
		if x < 0 {
			return 0
		}
		return x
	}

	p := chart.ScatterChart{Title: "Functions"}
	p.NSamples = 1 << 24
	p.XRange.Label, p.YRange.Label = "X - Value", "Y - Value"
	p.XRange.MinMode.Fixed, p.XRange.MaxMode.Fixed = true, true
	p.XRange.MinMode.Value, p.XRange.MaxMode.Value = -0.1, 0.1
	p.YRange.MinMode.Fixed, p.YRange.MaxMode.Fixed = true, true
	p.YRange.MinMode.Value, p.YRange.MaxMode.Value = -0.1, 0.1
	p.XRange.TicSetting.Delta = 1 / 12.0
	p.XRange.TicSetting.Format = func(x float64) string { return fmt.Sprintf("%3.2f", x) }
	p.YRange.TicSetting.Delta = 1 / 10.0
	p.YRange.TicSetting.Format = func(x float64) string { return fmt.Sprintf("%3.2f", x) }
	p.AddFunc("hBig(x)", fF64, chart.PlotStyleLines, chart.Style{Symbol: 'o', LineWidth: 1, LineColor: color.NRGBA{0x00, 0x00, 0xFF, 0xa0}, LineStyle: 0})
	p.AddFunc("minimax", hminimax, chart.PlotStyleLines, chart.Style{Symbol: 'o', LineWidth: 1, LineColor: color.NRGBA{0x00, 0xFF, 0xa0, 0xff}, LineStyle: 0})

	dumper.Plot(&p)
	dumper.Close()
}

var Background = color.RGBA{0xff, 0xff, 0xff, 0xff}

// -------------------------------------------------------------------------
// Dumper

// Dumper helps saving plots of size WxH in a NxM grid layout
// in several formats
type Dumper struct {
	N, M, W, H, Cnt int
	I               *image.RGBA
	imgFile         *os.File
}

func NewDumper(name string, n, m, w, h int) *Dumper {
	var err error
	dumper := Dumper{N: n, M: m, W: w, H: h}

	dumper.imgFile, err = os.Create(name + ".png")
	if err != nil {
		panic(err)
	}
	dumper.I = image.NewRGBA(image.Rect(0, 0, n*w, m*h))
	bg := image.NewUniform(color.RGBA{0xff, 0xff, 0xff, 0xff})
	draw.Draw(dumper.I, dumper.I.Bounds(), bg, image.ZP, draw.Src)

	return &dumper
}
func (d *Dumper) Close() {
	png.Encode(d.imgFile, d.I)
	d.imgFile.Close()
}

func (d *Dumper) Plot(c chart.Chart) {
	row, col := d.Cnt/d.N, d.Cnt%d.N
	igr := imgg.AddTo(d.I, col*d.W, row*d.H, d.W, d.H, color.RGBA{0xff, 0xff, 0xff, 0xff}, nil, nil)
	c.Plot(igr)
	d.Cnt++
}
