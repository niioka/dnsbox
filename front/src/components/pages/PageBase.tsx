import type {ReactNode} from "react";

type Props = {
    children: ReactNode
}

export const PageBase = ({ children }: Props) => {
    return (
        <div className="h-dvh p-4">
            {children}
        </div>
    )
}