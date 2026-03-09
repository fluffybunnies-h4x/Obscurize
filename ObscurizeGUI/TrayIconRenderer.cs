using System;
using System.Drawing;
using System.Drawing.Drawing2D;

namespace Obscurize
{
    internal enum ShieldState
    {
        ActiveDefensive,  // Blue shield
        ActiveTrap,       // Amber shield
        Inactive          // Grey shield
    }

    /// <summary>
    /// Generates 16×16 and 32×32 shield icons programmatically using GDI+.
    /// No external .ico file is required.
    /// </summary>
    internal static class TrayIconRenderer
    {
        internal static Icon CreateShieldIcon(ShieldState state)
        {
            // Build a 32×32 bitmap; Windows will scale it for the tray.
            using Bitmap bmp = new(32, 32, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            using Graphics g = Graphics.FromImage(bmp);
            g.SmoothingMode     = SmoothingMode.AntiAlias;
            g.CompositingMode   = CompositingMode.SourceOver;
            g.Clear(Color.Transparent);

            Color fill, stroke, glyph;
            switch (state)
            {
                case ShieldState.ActiveDefensive:
                    fill   = Color.FromArgb(255, 32, 110, 220);   // Blue
                    stroke = Color.FromArgb(255, 15,  70, 160);
                    glyph  = Color.White;
                    break;
                case ShieldState.ActiveTrap:
                    fill   = Color.FromArgb(255, 210, 120,  20);  // Amber
                    stroke = Color.FromArgb(255, 160,  80,   0);
                    glyph  = Color.White;
                    break;
                default:
                    fill   = Color.FromArgb(255, 120, 120, 120);  // Grey
                    stroke = Color.FromArgb(255,  70,  70,  70);
                    glyph  = Color.FromArgb(200, 200, 200, 200);
                    break;
            }

            // Shield outline – classic heraldic shield polygon.
            PointF[] shield =
            {
                new( 4,  2),
                new(28,  2),
                new(28, 18),
                new(16, 30),
                new( 4, 18),
            };

            using SolidBrush fillBrush   = new(fill);
            using Pen        outlinePen  = new(stroke, 1.5f);

            g.FillPolygon(fillBrush, shield);
            g.DrawPolygon(outlinePen, shield);

            // Draw a small 'O' glyph in the centre of the shield.
            using Font    font      = new("Segoe UI", 12f, FontStyle.Bold, GraphicsUnit.Pixel);
            using Brush   glyphBrush = new SolidBrush(glyph);
            SizeF  textSize = g.MeasureString("O", font);
            g.DrawString("O", font, glyphBrush,
                         (32f - textSize.Width)  / 2f,
                         (24f - textSize.Height) / 2f);

            return Icon.FromHandle(bmp.GetHicon());
        }
    }
}
