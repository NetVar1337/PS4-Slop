// app/src/components/IconButton.tsx
// Icon-only button. The tooltip text doubles as the accessible name: the
// global tooltip layer is pointer/focus driven and invisible to screen
// readers, so every icon button must carry an aria-label

import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";

type Props = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "aria-label"> & {
  /** Tooltip and accessible name. */
  tip: string;
  /** Pressed state for toggles (renders aria-pressed + data-active). */
  pressed?: boolean;
  /** Visual style: square icon button, bordered row action, or only `className`. */
  variant?: "icon" | "row" | "bare";
  children: ReactNode;
};

const IconButton = forwardRef<HTMLButtonElement, Props>(function IconButton(
  { tip, pressed, variant = "icon", className, children, type = "button", ...rest },
  ref,
) {
  const base = variant === "icon" ? "icon-button" : variant === "row" ? "row-action" : "";
  const cls = [base, className ?? ""].filter((c) => c !== "").join(" ");
  return (
    <button
      ref={ref}
      type={type}
      className={cls}
      data-tip={tip}
      aria-label={tip}
      {...(pressed !== undefined ? { "aria-pressed": pressed, "data-active": pressed } : {})}
      {...rest}
    >
      {children}
    </button>
  );
});

export default IconButton;
