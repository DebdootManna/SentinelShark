using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Media;

namespace SentinelSharkDotNet.UI.Controls;

public class SparklineControl : FrameworkElement
{
    private readonly Queue<double> _values = new();
    private const int MaxPoints = 30;

    public SparklineControl()
    {
        MinWidth = 120;
        MinHeight = 32;
        MaxHeight = 40;
    }

    public void AddValue(double kbps)
    {
        _values.Enqueue(kbps);
        if (_values.Count > MaxPoints)
        {
            _values.Dequeue();
        }
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        var rect = new Rect(0, 0, ActualWidth, ActualHeight);
        
        var bgBrush = new SolidColorBrush(Color.FromRgb(0x09, 0x0D, 0x16));
        bgBrush.Freeze();
        var borderPen = new Pen(new SolidColorBrush(Color.FromRgb(0x1E, 0x29, 0x3B)), 1);
        borderPen.Freeze();

        dc.DrawRoundedRectangle(bgBrush, borderPen, rect, 4, 4);

        if (_values.Count == 0) return;

        double maxVal = _values.Max();
        double w = ActualWidth;
        double h = ActualHeight;

        if (maxVal > 0.1)
        {
            var pts = _values.ToArray();
            double step = w / (MaxPoints - 1);
            var points = new Point[pts.Length];
            
            for (int i = 0; i < pts.Length; i++)
            {
                double x = i * step;
                double y = h - (pts[i] / maxVal) * (h - 10) - 5;
                points[i] = new Point(x, y);
            }

            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                ctx.BeginFigure(new Point(points[0].X, h), true, true);
                for (int i = 0; i < points.Length; i++)
                {
                    ctx.LineTo(points[i], true, true);
                }
                ctx.LineTo(new Point(points[^1].X, h), true, true);
            }
            geometry.Freeze();

            var gradient = new LinearGradientBrush(
                Color.FromArgb(120, 56, 189, 248),
                Color.FromArgb(5, 56, 189, 248),
                new Point(0, 0),
                new Point(0, 1));
            gradient.Freeze();

            dc.DrawGeometry(gradient, null, geometry);

            var lineGeometry = new StreamGeometry();
            using (var ctx = lineGeometry.Open())
            {
                ctx.BeginFigure(points[0], false, false);
                for (int i = 1; i < points.Length; i++)
                {
                    ctx.LineTo(points[i], true, true);
                }
            }
            lineGeometry.Freeze();

            var linePen = new Pen(new SolidColorBrush(Color.FromRgb(0x38, 0xBD, 0xF8)), 1.5);
            linePen.Freeze();
            dc.DrawGeometry(null, linePen, lineGeometry);

            var dotBrush = new SolidColorBrush(Color.FromRgb(0x34, 0xD3, 0x99));
            dotBrush.Freeze();
            dc.DrawEllipse(dotBrush, null, points[^1], 3.5, 3.5);
        }
        else
        {
            var dashPen = new Pen(new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55)), 1)
            {
                DashStyle = DashStyles.Dash
            };
            dashPen.Freeze();
            dc.DrawLine(dashPen, new Point(0, h / 2), new Point(w, h / 2));
        }
    }
}
